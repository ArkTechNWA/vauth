// Pre-generated bindings for linux/uhid.h
// Matches bindgen naming conventions expected by uhid-virt.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

pub const UHID_DATA_MAX: u32 = 4096;
pub const HID_MAX_DESCRIPTOR_SIZE: u32 = 4096;

// bindgen represents C enums as u32 type aliases + constants
pub type uhid_event_type = ::std::os::raw::c_uint;
pub const uhid_event_type___UHID_LEGACY_CREATE: uhid_event_type = 0;
pub const uhid_event_type_UHID_DESTROY: uhid_event_type = 1;
pub const uhid_event_type_UHID_START: uhid_event_type = 2;
pub const uhid_event_type_UHID_STOP: uhid_event_type = 3;
pub const uhid_event_type_UHID_OPEN: uhid_event_type = 4;
pub const uhid_event_type_UHID_CLOSE: uhid_event_type = 5;
pub const uhid_event_type_UHID_OUTPUT: uhid_event_type = 6;
pub const uhid_event_type___UHID_LEGACY_OUTPUT_EV: uhid_event_type = 7;
pub const uhid_event_type___UHID_LEGACY_INPUT: uhid_event_type = 8;
pub const uhid_event_type_UHID_GET_REPORT: uhid_event_type = 9;
pub const uhid_event_type_UHID_GET_REPORT_REPLY: uhid_event_type = 10;
pub const uhid_event_type_UHID_CREATE2: uhid_event_type = 11;
pub const uhid_event_type_UHID_INPUT2: uhid_event_type = 12;
pub const uhid_event_type_UHID_SET_REPORT: uhid_event_type = 13;
pub const uhid_event_type_UHID_SET_REPORT_REPLY: uhid_event_type = 14;

pub type uhid_dev_flag = ::std::os::raw::c_uint;
pub const uhid_dev_flag_UHID_DEV_NUMBERED_FEATURE_REPORTS: uhid_dev_flag = 1;
pub const uhid_dev_flag_UHID_DEV_NUMBERED_OUTPUT_REPORTS: uhid_dev_flag = 2;
pub const uhid_dev_flag_UHID_DEV_NUMBERED_INPUT_REPORTS: uhid_dev_flag = 4;

pub type uhid_report_type = ::std::os::raw::c_uint;
pub const uhid_report_type_UHID_FEATURE_REPORT: uhid_report_type = 0;
pub const uhid_report_type_UHID_OUTPUT_REPORT: uhid_report_type = 1;
pub const uhid_report_type_UHID_INPUT_REPORT: uhid_report_type = 2;

pub type uhid_legacy_event_type = ::std::os::raw::c_uint;
pub const uhid_legacy_event_type_UHID_CREATE: uhid_legacy_event_type = 0;
pub const uhid_legacy_event_type_UHID_OUTPUT_EV: uhid_legacy_event_type = 7;
pub const uhid_legacy_event_type_UHID_INPUT: uhid_legacy_event_type = 8;
pub const uhid_legacy_event_type_UHID_FEATURE: uhid_legacy_event_type = 9;
pub const uhid_legacy_event_type_UHID_FEATURE_ANSWER: uhid_legacy_event_type = 10;

// Also need hid_report_type from linux/hid.h (used by uhid-virt)
pub type hid_report_type = ::std::os::raw::c_uint;
pub const hid_report_type_HID_INPUT_REPORT: hid_report_type = 0;
pub const hid_report_type_HID_OUTPUT_REPORT: hid_report_type = 1;
pub const hid_report_type_HID_FEATURE_REPORT: hid_report_type = 2;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_create2_req {
    pub name: [u8; 128],
    pub phys: [u8; 64],
    pub uniq: [u8; 64],
    pub rd_size: u16,
    pub bus: u16,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    pub rd_data: [u8; HID_MAX_DESCRIPTOR_SIZE as usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct uhid_start_req {
    pub dev_flags: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_input2_req {
    pub size: u16,
    pub data: [u8; UHID_DATA_MAX as usize],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_output_req {
    pub data: [u8; UHID_DATA_MAX as usize],
    pub size: u16,
    pub rtype: u8,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_get_report_req {
    pub id: u32,
    pub rnum: u8,
    pub rtype: u8,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_get_report_reply_req {
    pub id: u32,
    pub err: u16,
    pub size: u16,
    pub data: [u8; UHID_DATA_MAX as usize],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_set_report_req {
    pub id: u32,
    pub rnum: u8,
    pub rtype: u8,
    pub size: u16,
    pub data: [u8; UHID_DATA_MAX as usize],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_set_report_reply_req {
    pub id: u32,
    pub err: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_create_req {
    pub name: [u8; 128],
    pub phys: [u8; 64],
    pub uniq: [u8; 64],
    pub rd_data: *mut u8,
    pub rd_size: u16,
    pub bus: u16,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_input_req {
    pub data: [u8; UHID_DATA_MAX as usize],
    pub size: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_output_ev_req {
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_feature_req {
    pub id: u32,
    pub rnum: u8,
    pub rtype: u8,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_feature_answer_req {
    pub id: u32,
    pub err: u16,
    pub size: u16,
    pub data: [u8; UHID_DATA_MAX as usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union uhid_event_u {
    pub create: uhid_create_req,
    pub input: uhid_input_req,
    pub output: uhid_output_req,
    pub output_ev: uhid_output_ev_req,
    pub feature: uhid_feature_req,
    pub get_report: uhid_get_report_req,
    pub feature_answer: uhid_feature_answer_req,
    pub get_report_reply: uhid_get_report_reply_req,
    pub create2: uhid_create2_req,
    pub input2: uhid_input2_req,
    pub set_report: uhid_set_report_req,
    pub set_report_reply: uhid_set_report_reply_req,
    pub start: uhid_start_req,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct uhid_event {
    pub type_: u32,
    pub u: uhid_event_u,
}
