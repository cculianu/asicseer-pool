#pragma once

#ifdef __cplusplus

#include <concepts>
#include <functional>
#include <type_traits>
#include <utility>

template <std::invocable Func = std::function<void()>>
class Defer
{
    Func f;
    bool disabled = false;
public:
    explicit Defer(Func && fun) : f(std::move(fun)) {}
    explicit Defer(const Func & fun) : f(fun) {}

    Defer(const Defer &d) : Defer(d.f) { disabled = d.disabled; }
    Defer(Defer &&d) : Defer(std::move(d.f)) { disabled = d.disabled; d.disabled = true; }

    ~Defer() { if (!disabled) f(); }

    Defer &operator=(const Defer &d) {
        f = d.f;
        disabled = d.disabled;
        return *this;
    }

    Defer &operator=(Defer &&d) {
        f = std::move(d.f);
        disabled = d.disabled;
        d.disabled = true;
        return *this;
    }

    void disable() { disabled = true; }
    void enable() { disabled = false; }
    operator bool() const { return !disabled; }
};

template<typename T>
concept ByteLike = std::is_standard_layout_v<T> && std::is_trivial_v<T> && sizeof(T) == 1
                   && !std::is_same_v<std::remove_cv_t<T>, bool>;

#endif // __cplusplus
