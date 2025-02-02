using System.Security.Cryptography;
using Geralt;

namespace XChaCha20SivDotNet;

public static class XChaCha20Siv
{
    public const int KeySize = XChaCha20.KeySize;
    public const int NonceSize = 16;
    public const int TagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkeys = stackalloc byte[KeySize * 2], macKey = subkeys[..KeySize], encKey = subkeys[KeySize..];
        BLAKE2b.ComputeTag(subkeys, ReadOnlySpan<byte>.Empty, key);

        Span<byte> tag = ciphertext[^TagSize..];
        S2v(tag, plaintext, nonce, macKey, associatedData);

        XChaCha20.Encrypt(ciphertext[..^TagSize], plaintext, tag[..XChaCha20.NonceSize], encKey);
        CryptographicOperations.ZeroMemory(subkeys);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkeys = stackalloc byte[KeySize * 2], macKey = subkeys[..KeySize], encKey = subkeys[KeySize..];
        BLAKE2b.ComputeTag(subkeys, ReadOnlySpan<byte>.Empty, key);

        ReadOnlySpan<byte> tag = ciphertext[^TagSize..];
        XChaCha20.Decrypt(plaintext, ciphertext[..^TagSize], tag[..XChaCha20.NonceSize], encKey);

        Span<byte> computedTag = stackalloc byte[TagSize];
        S2v(computedTag, plaintext, nonce, macKey, associatedData);

        bool valid = ConstantTime.Equals(tag, computedTag);
        CryptographicOperations.ZeroMemory(subkeys);
        CryptographicOperations.ZeroMemory(computedTag);

        if (!valid) {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException();
        }
    }

    private static void S2v(Span<byte> tag, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> macKey, ReadOnlySpan<byte> associatedData)
    {
        Span<byte> d = stackalloc byte[TagSize];
        BLAKE2b.ComputeTag(d, new byte[TagSize], macKey);

        if (associatedData.Length > 0) {
            S2vDbl256(d);
            BLAKE2b.ComputeTag(tag, associatedData, macKey);
            S2vXor(d, tag, d.Length);
        }

        if (nonce.Length > 0) {
            S2vDbl256(d);
            BLAKE2b.ComputeTag(tag, nonce, macKey);
            S2vXor(d, tag, d.Length);
        }

        using var blake2b = new IncrementalBLAKE2b(TagSize, macKey);
        if (plaintext.Length >= TagSize) {
            blake2b.Update(plaintext[..^TagSize]);
            S2vXor(d, plaintext[^TagSize..], TagSize);
        }
        else {
            S2vDbl256(d);
            S2vXor(d, plaintext, plaintext.Length);
            d[plaintext.Length] ^= 0x80;
        }
        blake2b.Update(d);
        blake2b.Finalize(tag);
    }

    private static void S2vDbl256(Span<byte> d)
    {
        Span<byte> t = stackalloc byte[d.Length];
        d.CopyTo(t);
        for (int i = 0; i < t.Length; i++) {
            t[i] = (byte)(t[i] << 1);
        }
        for (int i = 0; i < t.Length - 1; i++) {
            t[i] |= (byte)(d[i + 1] >> 7);
        }
        byte mask = (byte)~((d[0] >> 7) - 1);
        t[30] ^= (byte)(0x04 & mask);
        t[31] ^= (byte)(0x25 & mask);
        t.CopyTo(d);
        CryptographicOperations.ZeroMemory(t);
    }

    private static void S2vXor(Span<byte> d, ReadOnlySpan<byte> h, int length)
    {
        for (int i = 0; i < length; i++) {
            d[i] ^= h[i];
        }
    }
}
