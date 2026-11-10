//
//  ReceiptParser.swift
//  sandbox
//
//  Reads Apple StoreKit receipts (PKCS#7 / ASN.1) and StoreKit 2 JWS
//  transactions. Used to show sandbox subscription state without StoreKit.
//
//  Receipt layout: a PKCS#7 SignedData whose encapsulated content is an
//  OCTET STRING holding a SET of `SEQUENCE { INTEGER type, INTEGER version,
//  <value> }` attributes. Type 17 carries a SET of in-app purchases, each one
//  built the same way.
//

import Foundation

// MARK: - Minimal DER reader

struct DERNode {
    let tag: UInt8
    /// Content range inside the owning document's byte array.
    let range: Range<Int>
    var children: [DERNode] = []

    var isConstructed: Bool { (tag & 0x20) != 0 }
    var isSequence: Bool { tag == 0x30 }
    var isSet: Bool { tag == 0x31 }
    var isInteger: Bool { tag == 0x02 }
    var isOctetString: Bool { tag == 0x04 }
    var isTextual: Bool {
        tag == 0x0C || tag == 0x13 || tag == 0x16 || tag == 0x1A || tag == 0x17 || tag == 0x18
    }
}

struct DERDocument {
    let bytes: [UInt8]

    static func readLength(_ bytes: [UInt8], _ offset: inout Int) -> Int? {
        guard offset < bytes.count else { return nil }
        let first = bytes[offset]
        offset += 1
        if first & 0x80 == 0 { return Int(first) }
        let count = Int(first & 0x7F)
        guard count > 0, count <= 4, offset + count <= bytes.count else { return nil }
        var value = 0
        for _ in 0..<count {
            value = (value << 8) | Int(bytes[offset])
            offset += 1
        }
        return value
    }

    func parseNodes(in range: Range<Int>, depth: Int = 0) -> [DERNode] {
        guard depth < 24 else { return [] }
        var nodes: [DERNode] = []
        var offset = range.lowerBound
        while offset < range.upperBound {
            let start = offset
            let tag = bytes[offset]
            offset += 1
            guard let length = Self.readLength(bytes, &offset) else { break }
            guard length >= 0, offset + length <= range.upperBound else { break }
            var node = DERNode(tag: tag, range: offset..<(offset + length))
            if node.isConstructed {
                node.children = parseNodes(in: node.range, depth: depth + 1)
            }
            nodes.append(node)
            offset = node.range.upperBound
            if offset <= start { break }
        }
        return nodes
    }

    func text(_ node: DERNode) -> String? {
        guard node.isTextual || node.isOctetString else { return nil }
        return String(bytes: bytes[node.range], encoding: .utf8)
    }

    func integer(_ node: DERNode) -> Int? {
        guard node.isInteger, !node.range.isEmpty, node.range.count <= 8 else { return nil }
        var value = 0
        for index in node.range { value = (value << 8) | Int(bytes[index]) }
        return value
    }
}

// MARK: - Dates

enum ReceiptDate {
    private static let formats = [
        "yyyy-MM-dd HH:mm:ss VV",       // 2026-11-10 14:32:11 Etc/GMT
        "yyyy-MM-dd HH:mm:ss Z",
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd'T'HH:mm:ssZ",
        "yyMMddHHmmssZ",                // DER UTCTime
        "yyyyMMddHHmmssZ",              // DER GeneralizedTime
        "yyyyMMddHHmmss",
    ]

    private static let formatters: [DateFormatter] = formats.map { format in
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = format
        return formatter
    }

    static func parse(_ string: String?) -> Date? {
        guard let string = string?.trimmingCharacters(in: .whitespacesAndNewlines), !string.isEmpty else { return nil }
        for formatter in formatters {
            if let date = formatter.date(from: string) { return date }
        }
        return nil
    }
}

// MARK: - Receipt model

struct InAppReceipt {
    var productID: String?
    var quantity: Int = 1
    var transactionID: String?
    var originalTransactionID: String?
    var purchaseDate: Date?
    var originalPurchaseDate: Date?
    var expiresDate: Date?
    var cancellationDate: Date?
    var webOrderLineItemID: String?
    var isTrialPeriod = false
    var isInIntroOfferPeriod = false
}

struct ReceiptPayload {
    var receiptVersion: Int?
    var bundleID: String?
    var appVersion: String?
    var opaque: Data?
    var receiptCreationDate: Date?
    var originalAppVersion: String?
    var expirationDate: Date?
    var inApp: [InAppReceipt] = []
}

enum ReceiptParser {
    /// Parses a StoreKit receipt file. Returns nil when the bytes are not one.
    static func parse(_ data: Data) -> ReceiptPayload? {
        let bytes = [UInt8](data)
        guard bytes.count > 32 else { return nil }
        guard let payload = findPayload(bytes) else { return nil }
        let document = DERDocument(bytes: payload)
        return parsePayload(document)
    }

    /// The payload is the largest OCTET STRING whose content is an ASN.1 SET.
    /// In a PKCS#7 blob that is the encapsulated content, which sits before
    /// the certificates and signer infos.
    private static func findPayload(_ bytes: [UInt8]) -> [UInt8]? {
        var best: (length: Int, content: [UInt8])?

        var offset = 0
        while offset + 4 < bytes.count {
            guard bytes[offset] == 0x04 else { offset += 1; continue }
            var cursor = offset + 1
            guard let length = DERDocument.readLength(bytes, &cursor) else { offset += 1; continue }
            let end = cursor + length
            guard length > 32, end <= bytes.count, bytes[cursor] == 0x31 else { offset += 1; continue }
            if best == nil || length > best!.length {
                best = (length, Array(bytes[cursor..<end]))
            }
            offset = cursor
        }

        // Raw payload (no PKCS#7 wrapper).
        if best == nil, bytes[0] == 0x31 { return bytes }

        return best?.content
    }

    private static func parsePayload(_ document: DERDocument) -> ReceiptPayload? {
        let roots = document.parseNodes(in: 0..<document.bytes.count)
        guard let root = roots.first, root.isSet else { return nil }

        var payload = ReceiptPayload()
        var sawAttribute = false

        for field in root.children {
            guard field.isSequence,
                  let typeNode = field.children.first,
                  let type = document.integer(typeNode) else { continue }
            sawAttribute = true

            // Value is always the last element of the attribute sequence.
            guard let valueNode = field.children.last else { continue }

            if type == 17 {
                payload.inApp = parseInApp(valueNode, document: document)
                continue
            }

            let text = document.text(valueNode)
            switch type {
            case 0:  payload.receiptVersion = document.integer(valueNode)
            case 1:  payload.receiptVersion = text.flatMap(Int.init)
            case 2:  payload.bundleID = text
            case 3:  payload.appVersion = text
            case 4:  payload.opaque = valueNode.isOctetString ? Data(document.bytes[valueNode.range]) : nil
            case 12: payload.receiptCreationDate = ReceiptDate.parse(text)
            case 19: payload.originalAppVersion = text
            case 21: payload.expirationDate = ReceiptDate.parse(text)
            default: break
            }
        }
        return sawAttribute ? payload : nil
    }

    private static func parseInApp(_ node: DERNode, document: DERDocument) -> [InAppReceipt] {
        guard node.isSet || node.isSequence else { return [] }
        var result: [InAppReceipt] = []

        // Apple emits each in-app purchase as a SET of attributes; some
        // receipts (and reserialised copies) use SEQUENCE. Accept both.
        for entry in node.children where entry.isSequence || entry.isSet {
            var purchase = InAppReceipt()
            for field in entry.children {
                guard field.isSequence,
                      let typeNode = field.children.first,
                      let type = document.integer(typeNode),
                      let valueNode = field.children.last else { continue }
                let value = document.text(valueNode) ?? ""

                switch type {
                case 1701: purchase.quantity = Int(value) ?? 1
                case 1702: purchase.productID = value
                case 1703: purchase.transactionID = value
                case 1704: purchase.originalTransactionID = value
                case 1705: purchase.purchaseDate = ReceiptDate.parse(value)
                case 1706: purchase.originalPurchaseDate = ReceiptDate.parse(value)
                case 1707, 1708: purchase.expiresDate = ReceiptDate.parse(value)
                case 1709: purchase.webOrderLineItemID = value
                case 1712: purchase.cancellationDate = ReceiptDate.parse(value)
                case 1719: purchase.isInIntroOfferPeriod = value.lowercased() == "true"
                case 1721: purchase.isTrialPeriod = value.lowercased() == "true"
                default: break
                }
            }
            if purchase.productID != nil || purchase.transactionID != nil {
                result.append(purchase)
            }
        }
        return result
    }
}

// MARK: - StoreKit 2 JWS transactions

struct JWSTransaction {
    var productID: String?
    var transactionID: String?
    var originalTransactionID: String?
    var purchaseDate: Date?
    var expiresDate: Date?
    var revocationDate: Date?
    var environment: String?
    var type: String?
    var offerType: Int?
    var appAccountToken: String?
}

enum JWSParser {
    /// A StoreKit 2 transaction is `header.payload.signature` (base64url).
    static func parse(_ data: Data) -> JWSTransaction? {
        guard let text = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) else { return nil }
        let parts = text.split(separator: ".")
        guard parts.count == 3 else { return nil }
        guard let json = decodeBase64URL(String(parts[1])),
              let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any] else { return nil }

        var transaction = JWSTransaction()
        transaction.productID = object["productId"] as? String
        transaction.transactionID = object["transactionId"] as? String
        transaction.originalTransactionID = object["originalTransactionId"] as? String
        transaction.purchaseDate = milliseconds(object["purchaseDate"])
        transaction.expiresDate = milliseconds(object["expiresDate"])
        transaction.revocationDate = milliseconds(object["revocationDate"])
        transaction.environment = object["environment"] as? String
        transaction.type = object["type"] as? String
        transaction.offerType = object["offerType"] as? Int
        transaction.appAccountToken = object["appAccountToken"] as? String
        return transaction.productID == nil ? nil : transaction
    }

    private static func decodeBase64URL(_ string: String) -> Data? {
        var base64 = string.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64.append("=") }
        return Data(base64Encoded: base64)
    }

    private static func milliseconds(_ any: Any?) -> Date? {
        guard let number = any as? NSNumber else { return nil }
        return Date(timeIntervalSince1970: number.doubleValue / 1000)
    }
}
