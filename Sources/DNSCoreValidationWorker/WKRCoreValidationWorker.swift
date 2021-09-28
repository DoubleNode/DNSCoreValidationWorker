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
    public var passwordStrengthWorker: PTCLPasswordStrength = WKRCrashPasswordStrengthWorker()

    // MARK: - Business Logic / Single Item CRUD
    override open func intDoValidateBirthdate(for birthdate: Date?,
                                              with config: PTCLValidation.Data.Config.Birthdate,
                                              then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let birthdate = birthdate else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        let age = birthdate.dnsAge()
        guard config.minimumAge == nil || age.year >= config.minimumAge! else {
            return DNSError.Validation
                .tooLow(fieldName: config.fieldName,
                        DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumAge == nil || age.year <= config.maximumAge! else {
            return DNSError.Validation
                .tooHigh(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateCalendarDate(for calendarDate: Date?,
                                                 with config: PTCLValidation.Data.Config.CalendarDate,
                                                 then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let calendarDate = calendarDate else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimum == nil || calendarDate >= config.minimum! else {
            return DNSError.Validation
                .tooLow(fieldName: config.fieldName,
                        DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximum == nil || calendarDate <= config.maximum! else {
            return DNSError.Validation
                .tooHigh(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateEmail(for email: String?,
                                          with config: PTCLValidation.Data.Config.Email,
                                          then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let email = email else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !email.isEmpty else {
            return DNSError.Validation
                .required(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || email.dnsCheck(regEx: config.regex!) else {
            return DNSError.Validation
                .invalid(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateHandle(for handle: String?,
                                           with config: PTCLValidation.Data.Config.Handle,
                                           then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let handle = handle else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !handle.isEmpty else {
            return DNSError.Validation
                .required(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || handle.count >= config.minimumLength! else {
            return DNSError.Validation
                .tooShort(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || handle.count <= config.maximumLength! else {
            return DNSError.Validation
                .tooLong(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || handle.dnsCheck(regEx: config.regex!) else {
            return DNSError.Validation
                .invalid(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateName(for name: String?,
                                         with config: PTCLValidation.Data.Config.Name,
                                         then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let name = name else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !name.isEmpty else {
            return DNSError.Validation
                .required(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || name.count >= config.minimumLength! else {
            return DNSError.Validation
                .tooShort(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || name.count <= config.maximumLength! else {
            return DNSError.Validation
                .tooLong(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || name.dnsCheck(regEx: config.regex!) else {
            return DNSError.Validation
                .invalid(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateNumber(for numberString: String?,
                                           with config: PTCLValidation.Data.Config.Number,
                                           then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let number = Int64(numberString ?? "") else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimum == nil || number >= config.minimum! else {
            return DNSError.Validation
                .tooLow(fieldName: config.fieldName,
                        DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximum == nil || number <= config.maximum! else {
            return DNSError.Validation
                .tooHigh(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidatePassword(for password: String?,
                                             with config: PTCLValidation.Data.Config.Password,
                                             then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let password = password else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !password.isEmpty else {
            return DNSError.Validation
                .required(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || password.count >= config.minimumLength! else {
            return DNSError.Validation
                .tooShort(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || password.count <= config.maximumLength! else {
            return DNSError.Validation
                .tooLong(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        let strength = try! self.passwordStrengthWorker.doCheckPasswordStrength(for: password)
        guard strength.rawValue >= config.strength.rawValue else {
            return DNSError.Validation
                .tooWeak(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidatePercentage(for percentageString: String?,
                                               with config: PTCLValidation.Data.Config.Percentage,
                                               then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let percentage = Float(percentageString ?? "") else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimum == nil || percentage >= config.minimum! else {
            return DNSError.Validation
                .tooLow(fieldName: config.fieldName,
                        DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximum == nil || percentage <= config.maximum! else {
            return DNSError.Validation
                .tooHigh(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidatePhone(for phone: String?,
                                          with config: PTCLValidation.Data.Config.Phone,
                                          then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let phone = phone else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !phone.isEmpty else {
            return DNSError.Validation
                .required(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || phone.count >= config.minimumLength! else {
            return DNSError.Validation
                .tooShort(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || phone.count <= config.maximumLength! else {
            return DNSError.Validation
                .tooLong(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || phone.dnsCheck(regEx: config.regex!) else {
            return DNSError.Validation
                .invalid(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateSearch(for search: String?,
                                           with config: PTCLValidation.Data.Config.Search,
                                           then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let search = search else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !search.isEmpty else {
            return DNSError.Validation
                .required(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || search.count >= config.minimumLength! else {
            return DNSError.Validation
                .tooShort(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || search.count <= config.maximumLength! else {
            return DNSError.Validation
                .tooLong(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || search.dnsCheck(regEx: config.regex!) else {
            return DNSError.Validation
                .invalid(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateState(for state: String?,
                                          with config: PTCLValidation.Data.Config.State,
                                          then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let state = state else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !state.isEmpty else {
            return DNSError.Validation
                .required(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || state.count >= config.minimumLength! else {
            return DNSError.Validation
                .tooShort(fieldName: config.fieldName,
                          DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || state.count <= config.maximumLength! else {
            return DNSError.Validation
                .tooLong(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || state.dnsCheck(regEx: config.regex!) else {
            return DNSError.Validation
                .invalid(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func intDoValidateUnsignedNumber(for numberString: String?,
                                                   with config: PTCLValidation.Data.Config.UnsignedNumber,
                                                   then resultBlock: PTCLResultBlock?) throws -> DNSError.Validation? {
        _ = resultBlock?(.completed)
        guard let number = UInt64(numberString ?? "") else {
            return DNSError.Validation
                .noValue(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimum == nil || number >= config.minimum! else {
            return DNSError.Validation
                .tooLow(fieldName: config.fieldName,
                        DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximum == nil || number <= config.maximum! else {
            return DNSError.Validation
                .tooHigh(fieldName: config.fieldName,
                         DNSCodeLocation.validationWorker(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
}
