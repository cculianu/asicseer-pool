// Copyright (c) 2014-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <cstdlib>
#include <span>
#include <stdexcept>

/** A hasher class for SHA-512. */
class CSHA512
{
private:
    uint64_t s[8];
    unsigned char buf[128];
    uint64_t bytes{0};

public:
    static constexpr size_t OUTPUT_SIZE = 64;

    CSHA512();
    CSHA512& Write(const unsigned char* data, size_t len);
    CSHA512& Write(const std::span<const unsigned char> &data) { return Write(data.data(), data.size()); }
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    void Finalize(std::span<unsigned char> sp) {
        if (sp.size() >= OUTPUT_SIZE) Finalize(sp.data());
        else throw std::invalid_argument("CSHA512::Finalize() called with a std::span that lacks enough space!");
    }
    CSHA512& Reset();
    uint64_t Size() const { return bytes; }
};
