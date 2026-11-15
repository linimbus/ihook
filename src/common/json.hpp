// Minimal, dependency-free JSON value/parser/serializer for the ihook tools.
// Deliberately small: it supports the full JSON grammar needed by the wire
// protocol, preserves object key order, and stores numbers as their original
// textual token so 64-bit counters round-trip exactly.
#pragma once

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ijson {

class Value {
 public:
  enum class Type { Null, Bool, Number, String, Array, Object };

  Type type = Type::Null;
  bool boolean_value = false;
  std::string scalar;  // string contents, or raw numeric token
  std::vector<Value> items;
  std::vector<std::pair<std::string, Value>> members;

  Value() = default;

  static Value null() { return Value(); }
  static Value boolean(bool v) {
    Value out;
    out.type = Type::Bool;
    out.boolean_value = v;
    return out;
  }
  static Value number(long long v) {
    Value out;
    out.type = Type::Number;
    out.scalar = std::to_string(v);
    return out;
  }
  static Value number_u(unsigned long long v) {
    Value out;
    out.type = Type::Number;
    out.scalar = std::to_string(v);
    return out;
  }
  static Value number_raw(std::string token) {
    Value out;
    out.type = Type::Number;
    out.scalar = std::move(token);
    return out;
  }
  static Value string(std::string v) {
    Value out;
    out.type = Type::String;
    out.scalar = std::move(v);
    return out;
  }
  static Value array() {
    Value out;
    out.type = Type::Array;
    return out;
  }
  static Value object() {
    Value out;
    out.type = Type::Object;
    return out;
  }

  bool is_null() const { return type == Type::Null; }
  bool is_bool() const { return type == Type::Bool; }
  bool is_number() const { return type == Type::Number; }
  bool is_string() const { return type == Type::String; }
  bool is_array() const { return type == Type::Array; }
  bool is_object() const { return type == Type::Object; }

  bool as_bool(bool fallback = false) const {
    if (type == Type::Bool) return boolean_value;
    if (type == Type::Number) return as_i64(0) != 0;
    return fallback;
  }
  long long as_i64(long long fallback = 0) const {
    if (type != Type::Number && type != Type::String) return fallback;
    char* end = nullptr;
    long long v = std::strtoll(scalar.c_str(), &end, 10);
    if (end == scalar.c_str()) return fallback;
    return v;
  }
  unsigned long long as_u64(unsigned long long fallback = 0) const {
    if (type != Type::Number && type != Type::String) return fallback;
    char* end = nullptr;
    unsigned long long v = std::strtoull(scalar.c_str(), &end, 10);
    if (end == scalar.c_str()) return fallback;
    return v;
  }
  double as_double(double fallback = 0) const {
    if (type != Type::Number && type != Type::String) return fallback;
    char* end = nullptr;
    double v = std::strtod(scalar.c_str(), &end);
    if (end == scalar.c_str()) return fallback;
    return v;
  }
  const std::string& as_string() const { return scalar; }

  void push(Value v) {
    if (type != Type::Array) {
      type = Type::Array;
      items.clear();
    }
    items.push_back(std::move(v));
  }

  void set(std::string key, Value v) {
    if (type != Type::Object) {
      type = Type::Object;
      members.clear();
    }
    for (auto& kv : members) {
      if (kv.first == key) {
        kv.second = std::move(v);
        return;
      }
    }
    members.emplace_back(std::move(key), std::move(v));
  }

  const Value* find(std::string_view key) const {
    if (type != Type::Object) return nullptr;
    for (const auto& kv : members) {
      if (kv.first == key) return &kv.second;
    }
    return nullptr;
  }

  // Returns the string value at key, or fallback when absent / wrong type.
  std::string get_string(std::string_view key,
                         const std::string& fallback = std::string()) const {
    const Value* v = find(key);
    if (!v || v->type != Type::String) return fallback;
    return v->scalar;
  }

  bool get_bool(std::string_view key, bool fallback = false) const {
    const Value* v = find(key);
    return v ? v->as_bool(fallback) : fallback;
  }

  long long get_i64(std::string_view key, long long fallback = 0) const {
    const Value* v = find(key);
    return v ? v->as_i64(fallback) : fallback;
  }

  std::string dump(int indent = 0) const {
    std::string out;
    dump_into(*this, out, indent, 0);
    return out;
  }

  static Value parse(const std::string& text, std::string& error) {
    Parser p(text);
    error.clear();
    Value v;
    p.skip_ws();
    if (!p.parse_value(v)) {
      error = p.err.empty() ? "invalid JSON" : p.err;
      return Value();
    }
    p.skip_ws();
    if (p.pos != text.size()) {
      error = "trailing characters at offset " + std::to_string(p.pos);
      return Value();
    }
    return v;
  }

 private:
  static void append_utf8(std::string& out, uint32_t cp) {
    if (cp <= 0x7F) {
      out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  static void escape_into(const std::string& s, std::string& out) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned char c : s) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
          if (c < 0x20) {
            out += "\\u00";
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
          } else {
            out.push_back(static_cast<char>(c));
          }
      }
    }
  }

  static void indent_into(std::string& out, int indent, int depth) {
    if (indent > 0) {
      out.push_back('\n');
      out.append(static_cast<size_t>(indent) * static_cast<size_t>(depth), ' ');
    }
  }

  static void dump_into(const Value& v, std::string& out, int indent, int depth) {
    switch (v.type) {
      case Type::Null:
        out += "null";
        break;
      case Type::Bool:
        out += v.boolean_value ? "true" : "false";
        break;
      case Type::Number:
        out += v.scalar.empty() ? "0" : v.scalar;
        break;
      case Type::String:
        out.push_back('"');
        escape_into(v.scalar, out);
        out.push_back('"');
        break;
      case Type::Array:
        if (v.items.empty()) {
          out += "[]";
          break;
        }
        out.push_back('[');
        for (size_t i = 0; i < v.items.size(); ++i) {
          if (i) out.push_back(',');
          indent_into(out, indent, depth + 1);
          dump_into(v.items[i], out, indent, depth + 1);
        }
        indent_into(out, indent, depth);
        out.push_back(']');
        break;
      case Type::Object:
        if (v.members.empty()) {
          out += "{}";
          break;
        }
        out.push_back('{');
        for (size_t i = 0; i < v.members.size(); ++i) {
          if (i) out.push_back(',');
          indent_into(out, indent, depth + 1);
          out.push_back('"');
          escape_into(v.members[i].first, out);
          out += "\":";
          if (indent > 0) out.push_back(' ');
          dump_into(v.members[i].second, out, indent, depth + 1);
        }
        indent_into(out, indent, depth);
        out.push_back('}');
        break;
    }
  }

  class Parser {
   public:
    explicit Parser(const std::string& s) : text(s) {}

    std::string err;
    size_t pos = 0;

    void skip_ws() {
      while (pos < text.size()) {
        char c = text[pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
          ++pos;
        } else {
          break;
        }
      }
    }

    bool fail(const std::string& msg) {
      if (err.empty()) err = msg + " at offset " + std::to_string(pos);
      return false;
    }

    bool parse_value(Value& out) {
      skip_ws();
      if (pos >= text.size()) return fail("unexpected end of input");
      char c = text[pos];
      if (c == '{') return parse_object(out);
      if (c == '[') return parse_array(out);
      if (c == '"') {
        std::string s;
        if (!parse_string(s)) return false;
        out.type = Value::Type::String;
        out.scalar = std::move(s);
        return true;
      }
      if (c == 't') return parse_literal("true", Value::boolean(true), out);
      if (c == 'f') return parse_literal("false", Value::boolean(false), out);
      if (c == 'n') return parse_literal("null", Value::null(), out);
      if (c == '-' || (c >= '0' && c <= '9')) return parse_number(out);
      return fail("unexpected character");
    }

    bool parse_literal(std::string_view lit, Value value, Value& out) {
      if (text.compare(pos, lit.size(), lit) != 0) return fail("invalid literal");
      pos += lit.size();
      out = std::move(value);
      return true;
    }

    bool parse_number(Value& out) {
      size_t start = pos;
      if (pos < text.size() && text[pos] == '-') ++pos;
      if (pos >= text.size() || !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        return fail("invalid number");
      }
      if (text[pos] == '0') {
        ++pos;
      } else {
        while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) ++pos;
      }
      if (pos < text.size() && text[pos] == '.') {
        ++pos;
        if (pos >= text.size() || !std::isdigit(static_cast<unsigned char>(text[pos]))) {
          return fail("invalid fraction");
        }
        while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) ++pos;
      }
      if (pos < text.size() && (text[pos] == 'e' || text[pos] == 'E')) {
        ++pos;
        if (pos < text.size() && (text[pos] == '+' || text[pos] == '-')) ++pos;
        if (pos >= text.size() || !std::isdigit(static_cast<unsigned char>(text[pos]))) {
          return fail("invalid exponent");
        }
        while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) ++pos;
      }
      out.type = Value::Type::Number;
      out.scalar = text.substr(start, pos - start);
      return true;
    }

    bool parse_hex4(uint32_t& cp) {
      if (pos + 4 > text.size()) return fail("truncated \\u escape");
      cp = 0;
      for (int i = 0; i < 4; ++i) {
        char c = text[pos++];
        cp <<= 4;
        if (c >= '0' && c <= '9') {
          cp |= static_cast<uint32_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
          cp |= static_cast<uint32_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
          cp |= static_cast<uint32_t>(c - 'A' + 10);
        } else {
          return fail("invalid hex digit in \\u escape");
        }
      }
      return true;
    }

    bool parse_string(std::string& out) {
      if (pos >= text.size() || text[pos] != '"') return fail("expected string");
      ++pos;
      out.clear();
      while (pos < text.size()) {
        unsigned char c = static_cast<unsigned char>(text[pos++]);
        if (c == '"') return true;
        if (c == '\\') {
          if (pos >= text.size()) return fail("truncated escape");
          char e = text[pos++];
          switch (e) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
              uint32_t cp = 0;
              if (!parse_hex4(cp)) return false;
              if (cp >= 0xD800 && cp <= 0xDBFF && pos + 6 <= text.size() &&
                  text[pos] == '\\' && text[pos + 1] == 'u') {
                size_t save = pos;
                pos += 2;
                uint32_t low = 0;
                if (!parse_hex4(low)) return false;
                if (low >= 0xDC00 && low <= 0xDFFF) {
                  cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                } else {
                  pos = save;
                }
              }
              Value::append_utf8(out, cp);
              break;
            }
            default:
              return fail("invalid escape");
          }
        } else {
          if (c < 0x20) return fail("unescaped control character in string");
          out.push_back(static_cast<char>(c));
        }
      }
      return fail("unterminated string");
    }

    bool parse_array(Value& out) {
      ++pos;  // '['
      out = Value::array();
      skip_ws();
      if (pos < text.size() && text[pos] == ']') {
        ++pos;
        return true;
      }
      while (true) {
        Value v;
        if (!parse_value(v)) return false;
        out.items.push_back(std::move(v));
        skip_ws();
        if (pos >= text.size()) return fail("unterminated array");
        if (text[pos] == ',') {
          ++pos;
          continue;
        }
        if (text[pos] == ']') {
          ++pos;
          return true;
        }
        return fail("expected ',' or ']'");
      }
    }

    bool parse_object(Value& out) {
      ++pos;  // '{'
      out = Value::object();
      skip_ws();
      if (pos < text.size() && text[pos] == '}') {
        ++pos;
        return true;
      }
      while (true) {
        skip_ws();
        std::string key;
        if (!parse_string(key)) return false;
        skip_ws();
        if (pos >= text.size() || text[pos] != ':') return fail("expected ':'");
        ++pos;
        Value v;
        if (!parse_value(v)) return false;
        out.members.emplace_back(std::move(key), std::move(v));
        skip_ws();
        if (pos >= text.size()) return fail("unterminated object");
        if (text[pos] == ',') {
          ++pos;
          continue;
        }
        if (text[pos] == '}') {
          ++pos;
          return true;
        }
        return fail("expected ',' or '}'");
      }
    }

   private:
    const std::string& text;
  };
};

}  // namespace ijson
