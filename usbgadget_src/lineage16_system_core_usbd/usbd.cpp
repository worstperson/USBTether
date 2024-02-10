/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "usbgadget"

#include <string>

#include <android-base/logging.h>
#include <android/hardware/usb/gadget/1.0/IUsbGadget.h>

#include <hidl/HidlTransportSupport.h>

using android::hardware::usb::gadget::V1_0::IUsbGadget;
using android::hardware::Return;

int main(int argc, char** argv) {
    if (argc > 1) {
        android::sp<IUsbGadget> gadget = IUsbGadget::getService();
        Return<void> ret;

        if (gadget != nullptr) {
            LOG(INFO) << "Usb HAL found.";
            uint64_t function = std::strtoull(argv[1], NULL, 0);
            std::string message = "Setting USB mode to ";
            LOG(INFO) << message.append(argv[1]);
            ret = gadget->setCurrentUsbFunctions(function, nullptr, 0);
            if (ret.isOk()) exit(0);
            LOG(ERROR) << "Error while invoking usb hal";
        } else {
            LOG(INFO) << "Usb HAL not found";
        }
    } else {
        LOG(INFO) << "Usb config argument missing";
    }
    exit(1);
}
