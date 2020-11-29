import Security
import Foundation

enum PasswordType {
    case generic
    case internet

    internal var secClass: CFString {
        switch self {
        case .generic:
            return kSecClassGenericPassword
        case .internet:
            return kSecClassInternetPassword
        }
    }
}

public class KeychainStorage {
    private let account: String
    private let type: PasswordType

    init(account: String, type: PasswordType) {
        self.account = account
        self.type = type
    }

    var baseQuery: [String: AnyObject] {
        return [
            kSecClass as String: type.secClass,
            kSecAttrAccount as String: account as AnyObject,
        ]
    }

    var query: [String: AnyObject] {
        return baseQuery.adding(key: kSecMatchLimit as String, value: kSecMatchLimitOne)
    }

    func read() -> String? {
        let query = self.query.adding(key: kSecReturnData as String, value: true as AnyObject)
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status != errSecItemNotFound else { return nil }

        guard let data = result as? Data, let string = String(data: data, encoding: .utf8) else {
            return nil
        }
        return string
    }

    func update(_ secret: String) {
         guard let secretData = secret.data(using: .utf8) else { return }
        let dictionary: [String: AnyObject] = [kSecValueData as String: secretData as AnyObject]
        SecItemUpdate(baseQuery as CFDictionary, dictionary as CFDictionary)
    }

    func add(_ secret: String) {
        guard let secretData = secret.data(using: .utf8) else { return }
        let dictionary = baseQuery.adding(key: kSecValueData as String, value: secretData as AnyObject)
        SecItemAdd(dictionary as CFDictionary, nil)
    }

    func delete() throws {
        // SecItemDelete seems to fail with errSecItemNotFound if the item does not exist in the keychain. Is this expected behavior?
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status != errSecItemNotFound else { return }
        try throwIfNotZero(status)
    }

}

@propertyWrapper
public final class InternetPasswordStorage: KeychainStorage {

    private let server: String
    private let protocolType: String
    private let synchronizable: Bool
    private let accessGroup: String?

    public init(_ account: String, server: String, protocolType: String, synchronizable: Bool = false, accessGroup: String? = nil) {
        self.server = server
        self.protocolType = protocolType
        self.accessGroup = accessGroup
        self.synchronizable = synchronizable
        super.init(account: account, type: .internet)
    }

    override var baseQuery: [String: AnyObject] {
        var base = super.baseQuery

        // add Server
        base[kSecAttrServer as String] = server as AnyObject
        base[kSecAttrProtocol as String] = kSecAttrProtocolHTTPS

        if synchronizable {
            base[kSecAttrSynchronizable as String] = true as AnyObject
        }

        if let accessGroup = self.accessGroup {
            base[kSecAttrAccessGroup as String] = accessGroup as AnyObject
        }

        return base
    }

    override var query: [String: AnyObject] {
        return self.baseQuery.adding(key: kSecMatchLimit as String, value: kSecMatchLimitOne)
    }

    public var wrappedValue: String? {
        get {
            read()
        }
        set {
            if let v = newValue {
                if read() == nil {
                    add(v)
                } else {
                    update(v)
                }
            } else {
                try? delete()
            }
        }
    }
}

@propertyWrapper
public final class PasswordStorage: KeychainStorage {
    private let service: String
    private let accessGroup: String?
    private let synchronizable: Bool

    public init(_ account: String, service: String, synchronizable: Bool = false, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
        self.synchronizable = synchronizable
        super.init(account: account, type: .generic)
    }


    public var wrappedValue: String? {
        get {
            read()
        }
        set {
            if let v = newValue {
                if read() == nil {
                    add(v)
                } else {
                    update(v)
                }
            } else {
                try? delete()
            }
        }
    }

    override var baseQuery: [String: AnyObject] {
        var base = super.baseQuery

        // add Service
        base[kSecAttrService as String] = service as AnyObject

        if synchronizable {
            base[kSecAttrSynchronizable as String] = true as AnyObject
        }

        if let accessGroup = self.accessGroup {
            base[kSecAttrAccessGroup as String] = accessGroup as AnyObject
        }

        return base
    }

    override var query: [String: AnyObject] {
        return self.baseQuery.adding(key: kSecMatchLimit as String, value: kSecMatchLimitOne)
    }

}

extension Dictionary {
    func adding(key: Key, value: Value) -> Dictionary {
        var copy = self
        copy[key] = value
        return copy
    }
}

private func throwIfNotZero(_ status: OSStatus) throws {
    guard status != 0 else { return }
    throw KeychainError.keychainError(status: status)
}

public enum KeychainError: Error {
    case invalidData
    case keychainError(status: OSStatus)
}
