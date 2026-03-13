//
// /usr/include/linux/ethtool_netlink_generated.h
//

use neli::consts::genl::{Cmd, NlAttrType};
use neli::neli_enum;

pub const ETH_TOOL_GENL_NAME: &str = "ethtool";

///
/// ETHTOOL_MSG
///
#[neli_enum(serialized_type = "u8")]
#[non_exhaustive]
pub enum EthToolMessage {
    Unspecified = 0,
    LinkModesGet = 4,
}
impl Cmd for EthToolMessage {}

///
/// ETHTOOL_A_HEADER
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum EthToolHeaderAttribute {
    Unspecified = 0,
    DevIndex = 1,
    DevName = 2,
    Flags = 3,
    PhyIndex = 4,
}
impl NlAttrType for EthToolHeaderAttribute {}

///
/// ETHTOOL_A_LINKMODES
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum EthToolLinkModesAttribute {
    Unspecified = 0,
    Header = 1,
    AuthNeg = 2,
    Ours = 3,
    Peer = 4,
    Speed = 5,
    Duplex = 6,
    MasterSlaveCfg = 7,
    MasterSlaveState = 8,
    Lanes = 9,
    RateMatching = 10,
}
impl NlAttrType for EthToolLinkModesAttribute {}

///
/// ETHTOOL_A_BITSET
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum EthToolBitsetAttr {
    Unspecified = 0,
    NoMask = 1,
    Size = 2,
    Bits = 3,
    Value = 4,
    Mask = 5,
}
impl NlAttrType for EthToolBitsetAttr {}

///
/// ETHTOOL_A_BITSET_BIT
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum EthToolBitsetBitAttr {
    Unspecified = 0,
    Index = 1,
    Name = 2,
    Value = 3,
}
impl NlAttrType for EthToolBitsetBitAttr {}

///
/// ETHTOOL_LINK_MODE
///
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum EthToolLinkMode {
    Mode1000baseT_Half_BIT = 4,
    Mode1000baseT_Full_BIT = 5,
}
