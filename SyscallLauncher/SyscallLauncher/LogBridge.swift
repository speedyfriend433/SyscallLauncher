//
//  LogBridge.swift
//  SyscallLauncher
//
//  Created by 이지안.
//

import Foundation

extension Notification.Name {
    static let SyscallLog = Notification.Name("SyscallLog")
}
//remove @_cdecl
public func swiftSyscallLogCallback(_ message: UnsafePointer<CChar>) {
    let str = String(cString: message)
    NotificationCenter.default.post(name: .SyscallLog, object: nil, userInfo: ["message": str])
}
