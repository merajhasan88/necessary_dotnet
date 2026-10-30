// The iOS code_signing probe's parsing, on images built here: a signed thin
// image, a fat one resolved to its arm64 slice, an unsigned one -- reported as
// unsigned, never as a clean signed app -- and bytes that are no image.
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace Necessary.Tests
{
    public class MachOSigningTests
    {
        private const string Entitlements =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>"
            + "<key>application-identifier</key><string>ABCDE12345.com.example.app</string>"
            + "<key>com.apple.developer.team-identifier</key><string>ABCDE12345</string>"
            + "<key>get-task-allow</key><true/></dict></plist>";

        [Fact]
        public void A_signed_image_says_who_signed_it()
        {
            var result = MachOSigning.CodeSigning(Image(signed: true));
            Assert.Equal("ok", (string?)result["status"]);
            Assert.True((bool)result["signed"]!);
            Assert.Equal("com.example.app", (string?)result["signing_identifier"]);
            Assert.Equal("ABCDE12345", (string?)result["team_identifier"]);
            Assert.True((bool)result["get_task_allow"]!);
            Assert.Equal(3, (int)result["entitlement_count"]!);
            Assert.Equal(0x2_0002L, (long)result["code_directory_flags"]!);
            Assert.False(result.ContainsKey("signature_absent"));
        }

        [Fact]
        public void An_unsigned_image_is_unsigned_never_a_clean_signed_app()
        {
            var result = MachOSigning.CodeSigning(Image(signed: false));
            Assert.Equal("ok", (string?)result["status"]);
            Assert.False((bool)result["signed"]!);
            Assert.True((bool)result["signature_absent"]!);
            Assert.Equal(string.Empty, (string?)result["team_identifier"]);
        }

        [Fact]
        public void A_fat_image_is_read_at_its_arm64_slice()
        {
            var thin = Image(signed: true);
            var fat = new List<byte>();
            fat.AddRange(Be(0xcafebabe));
            fat.AddRange(Be(2));
            fat.AddRange(Be(0x01000007)); // x86_64, at an offset with no image
            fat.AddRange(Be(3));
            fat.AddRange(Be(4096));
            fat.AddRange(Be(16));
            fat.AddRange(Be(12));
            fat.AddRange(Be(0x0100000c)); // arm64
            fat.AddRange(Be(0));
            fat.AddRange(Be(8192));
            fat.AddRange(Be((uint)thin.Length));
            fat.AddRange(Be(14));
            while (fat.Count < 8192)
            {
                fat.Add(0);
            }

            fat.AddRange(thin);
            var result = MachOSigning.CodeSigning(fat.ToArray());
            Assert.True((bool)result["signed"]!);
            Assert.Equal("com.example.app", (string?)result["signing_identifier"]);
        }

        [Fact]
        public void Bytes_that_are_no_image_or_no_bytes_at_all_are_an_error()
        {
            var notAnImage = MachOSigning.CodeSigning(Encoding.ASCII.GetBytes("#!/bin/sh\necho not a Mach-O image\n"));
            Assert.Equal("error", (string?)notAnImage["status"]);
            Assert.Equal("The main executable is not a recognised 64-bit Mach-O image.", (string?)notAnImage["error"]);
            var unread = MachOSigning.CodeSigning(null);
            Assert.Equal("error", (string?)unread["status"]);
            Assert.Equal("The main executable could not be read.", (string?)unread["error"]);
        }

        [Fact]
        public void A_signature_that_is_no_superblob_is_named_as_such()
        {
            var image = Image(signed: true);
            var signatureAt = BitConverter.ToInt32(image, 32 + 8);
            image[signatureAt] = 0;
            var result = MachOSigning.CodeSigning(image);
            Assert.True((bool)result["signed"]!);
            Assert.Equal("Not an embedded signature SuperBlob.", (string?)result["signature_parse_error"]);
        }

        private static byte[] Le(uint value) => BitConverter.IsLittleEndian ? BitConverter.GetBytes(value) : Reverse(BitConverter.GetBytes(value));

        private static byte[] Be(uint value) => BitConverter.IsLittleEndian ? Reverse(BitConverter.GetBytes(value)) : BitConverter.GetBytes(value);

        private static byte[] Reverse(byte[] bytes)
        {
            Array.Reverse(bytes);
            return bytes;
        }

        /// <summary>A thin arm64 image: a header, one load command, and the signature it points at.</summary>
        private static byte[] Image(bool signed)
        {
            var image = new List<byte>();
            image.AddRange(Le(0xfeedfacf));
            image.AddRange(Le(0x0100000c));
            image.AddRange(Le(0));
            image.AddRange(Le(2));
            image.AddRange(Le(1));     // ncmds
            image.AddRange(Le(16));    // sizeofcmds
            image.AddRange(Le(0));
            image.AddRange(Le(0));

            // One load command: LC_CODE_SIGNATURE, or LC_UUID-sized filler when unsigned.
            image.AddRange(Le(signed ? 0x1dU : 0x1bU));
            image.AddRange(Le(16));
            image.AddRange(Le(signed ? 64U : 0U));
            var signature = Signature();
            image.AddRange(Le(signed ? (uint)signature.Length : 0U));
            while (image.Count < 64)
            {
                image.Add(0);
            }

            if (signed)
            {
                image.AddRange(signature);
            }

            return image.ToArray();
        }

        private static byte[] Signature()
        {
            var identifier = Encoding.UTF8.GetBytes("com.example.app\0");
            var codeDirectory = new List<byte>();
            codeDirectory.AddRange(Be(0xfade0c02));
            codeDirectory.AddRange(Be((uint)(44 + identifier.Length)));
            codeDirectory.AddRange(Be(0x20400));
            codeDirectory.AddRange(Be(0x2_0002)); // flags
            codeDirectory.AddRange(Be(0));        // hashOffset
            codeDirectory.AddRange(Be(44));       // identOffset
            while (codeDirectory.Count < 44)
            {
                codeDirectory.Add(0);
            }

            codeDirectory.AddRange(identifier);
            var plist = Encoding.UTF8.GetBytes(Entitlements);
            var entitlements = new List<byte>();
            entitlements.AddRange(Be(0xfade7171));
            entitlements.AddRange(Be((uint)(8 + plist.Length)));
            entitlements.AddRange(plist);

            const int header = 12 + (2 * 8);
            var superBlob = new List<byte>();
            superBlob.AddRange(Be(0xfade0cc0));
            superBlob.AddRange(Be((uint)(header + codeDirectory.Count + entitlements.Count)));
            superBlob.AddRange(Be(2));
            superBlob.AddRange(Be(0));
            superBlob.AddRange(Be(header));
            superBlob.AddRange(Be(5));
            superBlob.AddRange(Be((uint)(header + codeDirectory.Count)));
            superBlob.AddRange(codeDirectory);
            superBlob.AddRange(entitlements);
            return superBlob.ToArray();
        }
    }
}
