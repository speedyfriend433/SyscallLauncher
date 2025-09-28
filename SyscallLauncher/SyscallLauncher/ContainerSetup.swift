//
//  ContainerSetup.swift
//  SyscallLauncher
//
//  Created by 이지안 on 2025-09-28.
//

import Foundation
import Security

class ContainerSetup {
    
    static func generateKeychainGroup() -> String {
        let uuid = UUID()
        let group = "com.jian.syscalllauncher.container.\(uuid.uuidString.prefix(8))"
        print("Generated keychain group: \(group)")
        return String(group)
    }
    
    static func createAccessControl(for protection: CFString) -> SecAccessControl? {
        let flags: SecAccessControlCreateFlags = .privateKeyUsage
        var error: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(nil, protection, flags, &error)
        if let error = error {
            print("Access control error: \(error.takeRetainedValue())")
        }
        return accessControl
    }
    
    static func setupIsolation(for appID: String) -> Bool {
        let group = generateKeychainGroup()
        print("Setup isolation for \(appID) with group \(group)") //SecItemAdd with group later
        return true
    }
}
