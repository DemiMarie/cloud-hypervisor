// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

mod pci_common_config;
mod pci_device;
pub use pci_common_config::{VIRTIO_PCI_COMMON_CONFIG_ID, VirtioPciCommonConfig};
pub use pci_device::{
    MAX_DEVICE_AUXILIARY_NOTIFICATIONS, VirtioPciDevice, VirtioPciDeviceActivator,
    VirtioPciDeviceError, device_auxiliary_notification_addr,
};

pub trait VirtioTransport {
    fn ioeventfds(&self, base_addr: u64) -> pci_device::EventfdIterator<'_>;
}
