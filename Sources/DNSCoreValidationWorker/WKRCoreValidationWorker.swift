//
//  WKRCoreValidationWorker.swift
//  DoubleNode Swift Framework (DNSFramework) - DNSCoreValidationWorker
//
//  Created by Darren Ehlers.
//  Copyright © 2020 - 2016 DoubleNode.com. All rights reserved.
//

import DNSBlankWorkers
import DNSCore
import DNSCorePasswordStrengthWorker
import DNSCrashWorkers
import DNSError
import DNSProtocols
import Foundation

open class WKRCoreValidationWorker: WKRBlankValidationWorker
{
    public var passwordStrengthWorker: PTCLPasswordStrength_Protocol = WKRCrashPasswordStrengthWorker()

    // MARK: - Business Logic / Single Item CRUD
    override open func intDoValidateBirthdate(for birthdate: Date?,
                                              with config: PTCLValidationBirthdateConfig,
                                              then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let _/*birthdate*/ = birthdate else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimumAge == nil || number >= config.minimumAge! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximumAge == nil || number <= config.maximumAge! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
    override open func intDoValidateDate(for date: Date?,
                                         with config: PTCLValidationDateConfig,
                                         then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let _/*date*/ = date else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimum == nil || number >= config.minimum! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximum == nil || number <= config.maximum! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
    override open func intDoValidateEmail(for email: String?,
                                          with config: PTCLValidationEmailConfig,
                                          then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let email = email else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !email.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || email.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateHandle(for handle: String?,
                                           with config: PTCLValidationHandleConfig,
                                           then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let handle = handle else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !handle.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || handle.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || handle.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || handle.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateName(for name: String?,
                                         with config: PTCLValidationNameConfig,
                                         then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let name = name else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !name.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || name.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || name.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || name.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateNumber(for number: String?,
                                           with config: PTCLValidationNumberConfig,
                                           then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let _/*number*/ = number else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimum == nil || number >= config.minimum! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximum == nil || number <= config.maximum! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
    override open func intDoValidatePassword(for password: String?,
                                             with config: PTCLValidationPasswordConfig,
                                             then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let password = password else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !password.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || password.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || password.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        let strength = try! self.passwordStrengthWorker.doCheckPasswordStrength(for: password)
        guard strength.rawValue >= config.strength.rawValue else {
            return PTCLValidationError
                .tooWeak(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidatePercentage(for percentage: String?,
                                               with config: PTCLValidationPercentageConfig,
                                               then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let _/*percentage*/ = percentage else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimum == nil || number >= config.minimum! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximum == nil || number <= config.maximum! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
    override open func intDoValidatePhone(for phone: String?,
                                          with config: PTCLValidationPhoneConfig,
                                          then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let phone = phone else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !phone.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || phone.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || phone.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || phone.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateSearch(for search: String?,
                                           with config: PTCLValidationSearchConfig,
                                           then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let search = search else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !search.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || search.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || search.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || search.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateState(for state: String?,
                                          with config: PTCLValidationStateConfig,
                                          then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let state = state else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !state.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || state.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || state.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || state.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateUnsignedNumber(for number: String?,
                                                   with config: PTCLValidationUnsignedNumberConfig,
                                                   then resultBlock: PTCLResultBlock?) throws -> DNSError? {
        _ = resultBlock?(.completed)
        guard let _/*number*/ = number else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimum == nil || number >= config.minimum! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximum == nil || number <= config.maximum! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
}
