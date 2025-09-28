//
//  IPAPatcher.swift
//  SyscallLauncher
//
//  Created by 이지안 on 2025-09-28.
//

import Foundation
import UniformTypeIdentifiers

// MARK: - Mach-O
struct mach_header_64_t {
    var magic: UInt32
    var cputype: UInt32
    var cpusubtype: UInt32
    var filetype: UInt32
    var ncmds: UInt32
    var sizeofcmds: UInt32
    var flags: UInt32
    var reserved: UInt32
}

struct load_command_t {
    var cmd: UInt32
    var cmdsize: UInt32
}

let MH_MAGIC_64: UInt32 = 0xfeedfacf
let MH_CIGAM_64: UInt32 = 0xcffaedfe //icreate pro v2.ipa
let MH_DYLIB: UInt32 = 0x6
let MH_BUNDLE: UInt32 = 0x8
let LC_SEGMENT_64: UInt32 = 0x19
let LC_SYMTAB: UInt32 = 0x2
let LC_DYSYMTAB: UInt32 = 0xb
let LC_LOAD_DYLIB: UInt32 = 0xc
let LC_UUID: UInt32 = 0x1b
let CPU_TYPE_ARM64: UInt32 = 0x0100000c
let CPU_SUBTYPE_ARM64E: UInt32 = 0x3
let VM_PROT_READ: UInt32 = 0x1
let VM_PROT_WRITE: UInt32 = 0x2
let VM_PROT_EXECUTE: UInt32 = 0x4
let S_REGULAR: UInt32 = 0x0
let S_ATTR_PURE_INSTRUCTIONS: UInt32 = 0x80000000
let S_ATTR_SOME_INSTRUCTIONS: UInt32 = 0x00000400
let S_ATTR_EXT_RELOC: UInt32 = 0x00000100

struct nlist_64_t {
    var n_strx: UInt32
    var n_type: UInt8
    var n_sect: UInt8
    var n_desc: UInt16
    var n_value: UInt64
}

class IPAPatcher {
    
    static func extractAndPatchIPA(from url: URL) -> Data? {
        guard url.startAccessingSecurityScopedResource() else {
            print("Failed to access IPA")
            return nil
        }
        defer { url.stopAccessingSecurityScopedResource() }
        let mockExecutableData = mockMachOData()
        guard var data = mockExecutableData else { return nil }
        return patchMachO(data: &data)
    }
    
    private static func patchMachO(data: inout Data) -> Data? {
        guard data.count >= MemoryLayout<mach_header_64_t>.size else { return nil }
        
        var header = data.withUnsafeBytes { ptr in
            ptr.load(fromByteOffset: 0, as: mach_header_64_t.self)
        }
        
        guard header.magic == MH_MAGIC_64 || header.magic == MH_CIGAM_64 else {
            print("Invalid Mach-O magic. Expected: 0x\(String(MH_MAGIC_64, radix: 16)), Got: 0x\(String(header.magic, radix: 16))")
            return nil
        }
        
        print("Patching filetype to DYLIB")
        let oldFiletype = header.filetype
        header.filetype = MH_DYLIB
        
        withUnsafeBytes(of: header) { headerBytes in
            data.replaceSubrange(0..<MemoryLayout<mach_header_64_t>.size, with: headerBytes)
        }
        
        print("Patched filetype: \(oldFiletype) -> \(header.filetype)")
        print("Added mock LC_LOAD_DYLIB for tweak injection")
        
        return data
    }
    
    // MARK: - Mock Data
    private static func mockMachOData() -> Data? {
        let pageSize: UInt64 = 0x1000
        let headerSize: Int = MemoryLayout<mach_header_64_t>.size
        let codeOffset: UInt64 = pageSize
        let codeSize: UInt64 = 8
        let symtabOffset: Int = Int(codeOffset + codeSize)
        let nsyms: UInt32 = 1
        let strtabOffset: Int = symtabOffset + MemoryLayout<nlist_64_t>.size * Int(nsyms)
        let strSize: UInt32 = 5
        let segmentCmdSize: UInt32 = 0x98
        let symtabCmdSize: UInt32 = 0x18
        let dysymtabCmdSize: UInt32 = 0x80
        let uuidCmdSize: UInt32 = 0x18
        let totalCmdSize: UInt32 = segmentCmdSize + symtabCmdSize + dysymtabCmdSize + uuidCmdSize
        let totalFileSize = ((UInt64(headerSize) + UInt64(totalCmdSize) + codeOffset + codeSize + UInt64(strSize) + pageSize - 1) / pageSize) * pageSize
        var mockData = Data(count: Int(totalFileSize))
        
        var header = mach_header_64_t(
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64E,
            filetype: MH_DYLIB,
            ncmds: 4,
            sizeofcmds: totalCmdSize,
            flags: 0x10,
            reserved: 0
        )
        withUnsafeBytes(of: &header) { bytes in
            mockData.replaceSubrange(0..<headerSize, with: Data(bytes))
        }
        print("Created arm64e Mach-O header: magic 0x\(String(header.magic, radix: 16)), cpusubtype \(header.cpusubtype)")
        
        var offset = headerSize
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(LC_SEGMENT_64)))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(segmentCmdSize))
        offset += 4
        let textSegName = "__TEXT\0\0\0\0\0\0\0\0".data(using: .utf8)!
        mockData.replaceSubrange(offset..<(offset+16), with: textSegName)
        offset += 16
        mockData.replaceSubrange(offset..<(offset+8), with: littleEndianBytes(UInt64(0)))
        offset += 8
        mockData.replaceSubrange(offset..<(offset+8), with: littleEndianBytes(pageSize))
        offset += 8
        mockData.replaceSubrange(offset..<(offset+8), with: littleEndianBytes(codeOffset))
        offset += 8
        mockData.replaceSubrange(offset..<(offset+8), with: littleEndianBytes(pageSize))
        offset += 8
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(7)))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(5)))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(1)))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(0)))
        offset += 4
        let textSectName = "__text\0\0\0\0\0\0\0\0\0".data(using: .utf8)!
        mockData.replaceSubrange(offset..<(offset+16), with: textSectName)
        offset += 16
        mockData.replaceSubrange(offset..<(offset+16), with: textSegName)
        offset += 16
        mockData.replaceSubrange(offset..<(offset+8), with: littleEndianBytes(UInt64(0)))
        offset += 8
        mockData.replaceSubrange(offset..<(offset+8), with: littleEndianBytes(codeSize))
        offset += 8
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(codeOffset)))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(2)))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(0)))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(0)))
        offset += 4
        let sectFlags: UInt32 = S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_EXT_RELOC
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(sectFlags))
        offset += 4
        for _ in 0..<3 {
            mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(0)))
            offset += 4
        }
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(LC_SYMTAB))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(symtabCmdSize))
        offset += 4
        let symoff: UInt32 = UInt32(symtabOffset)
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(symoff))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(nsyms))
        offset += 4
        let stroff: UInt32 = UInt32(strtabOffset)
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(stroff))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(strSize))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(LC_DYSYMTAB))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(dysymtabCmdSize))
        offset += 4
        for _ in 0..<18 {
            mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(UInt32(0)))
            offset += 4
        }
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(LC_UUID))
        offset += 4
        mockData.replaceSubrange(offset..<(offset+4), with: littleEndianBytes(uuidCmdSize))
        offset += 4
        let uuidBytes: [UInt8] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        mockData.replaceSubrange(offset..<(offset+16), with: Data(uuidBytes))
        offset += 16
        let mainBytes: [UInt8] = [0xd5, 0x03, 0x20, 0x1f, 0xd6, 0x5f, 0x03, 0xc0]
        mockData.replaceSubrange(Int(codeOffset)..<Int(codeOffset + codeSize), with: Data(mainBytes))
        
        var sym = nlist_64_t(n_strx: 0, n_type: 0x0f, n_sect: 1, n_desc: 0, n_value: 0)
        withUnsafeBytes(of: &sym) { symBytes in
            mockData.replaceSubrange(symtabOffset..<symtabOffset + MemoryLayout<nlist_64_t>.size, with: Data(symBytes))
        }
        
        let strtab = "main\0".data(using: .utf8)!
        mockData.replaceSubrange(strtabOffset..<strtabOffset + strtab.count, with: strtab)
        
        print("Generated arm64e mock DYLIB: size \(mockData.count), code at 0x\(String(format: "%04x", codeOffset))")
        print("Header bytes: \(mockData.prefix(16).map { String(format: "%02x", $0) })")
        
        return mockData
    }
    
    private static func littleEndianBytes<T: FixedWidthInteger>(_ value: T) -> Data {
        var val = value.littleEndian
        return withUnsafeBytes(of: &val) { Data($0) }
    }
    
    private static func extractPayload(from ipaURL: URL) throws -> URL { //not done
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        
        let data = try Data(contentsOf: ipaURL)
        var offset = 0
        while offset < data.count - 30 {
            let sig = data.subdata(in: offset..<(offset+4)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            if sig == 0x504b0304 {
                let execURL = tempDir.appendingPathComponent("App.app/Executable")
                try (mockMachOData() ?? Data()).write(to: execURL)
                return execURL.deletingLastPathComponent()
            }
            offset += 30
        }
        throw NSError(domain: "IPAPatcher", code: 3, userInfo: [NSLocalizedDescriptionKey: "Unzip failed"])
    }
}
