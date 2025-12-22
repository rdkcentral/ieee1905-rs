//
// /usr/include/linux/nl80211.h
//

use neli::consts::genl::{Cmd, NlAttrType};
use neli::neli_enum;

pub const NL80211_GENL_NAME: &str = "nl80211";

///
/// enum nl80211_commands - supported nl80211 commands
///
#[neli_enum(serialized_type = "u8")]
#[non_exhaustive]
pub enum Nl80211Command {
    /// Request information about a wiphy or dump request to get a list of all present wiphys.
    GetWiphy = 1,
    /// Request an interface's configuration;
    /// either a dump request on a %NL80211_ATTR_WIPHY or a specific get
    /// on an %NL80211_ATTR_IFINDEX is supported.
    GetInterface = 5,
    /// Get station attributes for station identified by
    /// %NL80211_ATTR_MAC on the interface identified by %NL80211_ATTR_IFINDEX.
    GetStation = 17,
}
impl Cmd for Nl80211Command {}

///
/// enum nl80211_attrs - nl80211 netlink attributes
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum Nl80211Attribute {
    /// attribute number 0 is reserved
    Unspecified = 0,
    /// index of wiphy to operate on, cf. /sys/class/ieee80211/<phyname>/index
    Wiphy = 1,
    /// wiphy name (used for renaming)
    WiphyName = 2,
    /// network interface index of the device to operate on
    IfIndex = 3,
    /// network interface name
    IfName = 4,
    /// type of virtual interface, see &enum nl80211_iftype
    IfType = 5,
    /// MAC address (various uses)
    Mac = 6,
    /// information about a station, part of station info
    /// given for %NL80211_CMD_GET_STATION, nested attribute containing
    /// info as possible, see &enum nl80211_sta_info.
    StaInfo = 21,
    /// Information about an operating bands, consisting of a nested array.
    WiphyBands = 22,
    /// frequency of the selected channel in MHz, defines the channel together
    /// with the (deprecated) %NL80211_ATTR_WIPHY_CHANNEL_TYPE attribute or
    /// the attributes %NL80211_ATTR_CHANNEL_WIDTH and if needed %NL80211_ATTR_CENTER_FREQ1
    /// and %NL80211_ATTR_CENTER_FREQ2
    WiphyFreq = 38,
    /// included with NL80211_ATTR_WIPHY_FREQ if HT20 or HT40 are
    /// to be used (i.e., HT disabled if not included):
    /// NL80211_CHAN_NO_HT = HT not allowed (i.e., same as not including this attribute)
    /// NL80211_CHAN_HT20 = HT20 only
    /// NL80211_CHAN_HT40MINUS = secondary channel is below the primary channel
    /// NL80211_CHAN_HT40PLUS = secondary channel is above the primary channel
    /// This attribute is now deprecated.
    WiphyChannelType = 39,
    /// Used to indicate consistent snapshots for dumps. This number increases
    /// whenever the object list being dumped changes, and as such userspace
    /// can verify that it has obtained a complete and consistent snapshot
    /// by verifying that all dump messages contain the same generation number.
    /// If it changed then the list changed and the dump should be repeated
    /// completely from scratch.
    Generation = 46,
    /// SSID (binary attribute, 0..32 octets)
    Ssid = 52,
    /// Use 4-address frames on a virtual interface
    Addr4 = 83,
    /// Transmit power level in signed mBm units.
    /// This is used in association with @NL80211_ATTR_WIPHY_TX_POWER_SETTING
    /// for non-automatic settings.
    WiphyTxPowerLevel = 98,
    /// wireless device identifier, used for pseudo-devices that don't have a netdev (u64)
    Wdev = 153,
    /// u32 attribute containing one of the values of &enum nl80211_chan_width,
    /// describing the channel width. See the documentation of the enum for more information.
    ChannelWidth = 159,
    /// Center frequency of the first part of the channel, used for anything but
    /// 20 MHz bandwidth. In S1G this is the operating channel center frequency.
    CenterFreq1 = 160,
    /// Center frequency of the second part of the channel, used only for 80+80 MHz bandwidth
    CenterFreq2 = 161,
}
impl NlAttrType for Nl80211Attribute {}

///
/// enum nl80211_iftype - (virtual) interface types
///
#[neli_enum(serialized_type = "u32")]
#[non_exhaustive]
pub enum Nl80211IfType {
    /// attribute number 0 is reserved
    Unspecified = 0,
    /// independent BSS member
    AdHoc = 1,
    /// managed BSS member
    Station = 2,
    /// access point
    Ap = 3,
    /// VLAN interface for access points; VLAN interfaces are a bit special
    /// in that they must always be tied to a pre-existing AP type interface.
    ApVlan = 4,
    /// wireless distribution interface
    Wds = 5,
    /// monitor interface receiving all frames
    Monitor = 6,
    /// mesh point
    MeshPoint = 7,
    /// P2P client
    P2pClient = 8,
    /// P2P group owner
    P2pGo = 9,
    /// P2P device interface type, this is not a netdev
    /// and therefore can't be created in the normal ways, use the
    /// %NL80211_CMD_START_P2P_DEVICE and %NL80211_CMD_STOP_P2P_DEVICE
    /// commands to create and destroy one
    P2pDevice = 10,
    /// Outside Context of a BSS
    /// This mode corresponds to the MIB variable dot11OCBActivated=true
    Ocb = 11,
}

///
/// enum nl80211_sta_info - station information
///
/// These attribute types are used with %NL80211_ATTR_STA_INFO
/// when getting information about a station.
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum Nl80211StaInfo {
    /// attribute number 0 is reserved
    Unspecified = 0,
    /// time since last activity (u32, msecs)
    InactiveTime = 1,
    /// total received bytes (u32, from this station)
    RxBytes = 2,
    /// total transmitted bytes (u32, to this station)
    TxBytes = 3,
    /// the station's mesh LLID
    LLID = 4,
    /// the station's mesh PLID
    PLID = 5,
    /// peer link state for the station (see %enum nl80211_plink_state)
    PlinkState = 6,
    /// signal strength of last received PPDU (u8, dBm)
    Signal = 7,
    /// current unicast tx rate, nested attribute containing info as possible, see &enum nl80211_rate_info
    TxBitrate = 8,
    /// total received packet (u32, from this station)
    RxPackets = 9,
    /// total transmitted packets (u32, to this station)
    TxPackets = 10,
    /// total retries (u32, to this station)
    TxRetries = 11,
    /// total failed packets (u32, to this station)
    TxFailed = 12,
    /// signal strength average (u8, dBm)
    SignalAvg = 13,
    /// last unicast data frame rx rate, nested attribute, like NL80211_STA_INFO_TX_BITRATE.
    RxBitrate = 14,
    /// current station's view of BSS, nested attribute containing info as possible, see &enum nl80211_sta_bss_param
    BssParam = 15,
    /// time since the station is last connected
    ConnectedTime = 16,
    /// Contains a struct nl80211_sta_flag_update.
    StaFlags = 17,
    /// count of times beacon loss was detected (u32)
    BeaconLoss = 18,
    /// timing offset with respect to this STA (s64)
    TOffset = 19,
    /// local mesh STA link-specific power mode
    LocalPm = 20,
    /// peer mesh STA link-specific power mode
    PeerPm = 21,
    /// neighbor mesh STA power save mode towards non-peer STA
    NonPeerPm = 22,
    /// total received bytes (u64, from this station)
    RxBytes64 = 23,
    /// total transmitted bytes (u64, to this station)
    TxBytes64 = 24,
    /// per-chain signal strength of last PPDU
    /// Contains a nested array of signal strength attributes (u8, dBm)
    ChainSignal = 25,
    /// per-chain signal strength average
    /// Same format as NL80211_STA_INFO_CHAIN_SIGNAL.
    ChainSignalAvg = 26,
    /// expected throughput considering also the 802.11 header (u32, kbps)
    ExpectedThroughput = 27,
}
impl NlAttrType for Nl80211StaInfo {}

///
/// enum nl80211_rate_info - bitrate information
///
/// These attribute types are used with %NL80211_STA_INFO_TXRATE
/// when getting information about the bitrate of a station.
/// There are 2 attributes for bitrate, a legacy one that represents
/// a 16-bit value, and new one that represents a 32-bit value.
/// If the rate value fits into 16 bit, both attributes are reported
/// with the same value. If the rate is too high to fit into 16 bits
/// (>6.5535Gbps) only 32-bit attribute is included.
/// User space tools encouraged to use the 32-bit attribute and fall
/// back to the 16-bit one for compatibility with older kernels.
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum Nl80211RateInfo {
    /// attribute number 0 is reserved
    Unspecified = 0,
    /// total bitrate (u16, 100 kbps)
    Bitrate = 1,
    /// mcs index for 802.11n (u8)
    Mcs = 2,
    /// 40 MHz dual channel bitrate
    MhzWidth40 = 3,
    /// 400ns guard interval
    ShortGi = 4,
    /// total bitrate (u32, 100 kbps)
    Bitrate32 = 5,
    /// MCS index for VHT (u8)
    VhtMcs = 6,
    /// number of streams in VHT (u8)
    VhtNss = 7,
    /// 80 MHz VHT rate
    MhzWidth80 = 8,
    /// 80+80 MHz VHT rate
    Width80p80Mhz = 9,
    /// 160 MHz VHT rate
    MhzWidth160 = 10,
    /// 10 MHz width - note that this is
    /// a legacy rate and will be reported as the actual bitrate, i.e.
    /// half the base (20 MHz) rate
    MhzWidth10 = 11,
    /// 5 MHz width - note that this is
    /// a legacy rate and will be reported as the actual bitrate, i.e.
    /// a quarter of the base (20 MHz) rate
    MhzWidth5 = 12,
    /// HE MCS index (u8, 0-11)
    HeMcs = 13,
    /// HE NSS value (u8, 1-8)
    HeNss = 14,
    /// HE guard interval identifier (u8, see &enum nl80211_he_gi)
    HeGi = 15,
    /// HE DCM value (u8, 0/1)
    HeDcm = 16,
    /// HE RU allocation, if not present then non-OFDMA was used (u8, see &enum nl80211_he_ru_alloc)
    HeRuAlloc = 17,
    /// 320 MHz bitrate
    MhzWidth320 = 18,
    /// EHT MCS index (u8, 0-15)
    EhtMcs = 19,
    /// EHT NSS value (u8, 1-8)
    EhtNss = 20,
    /// EHT guard interval identifier (u8, see &enum nl80211_eht_gi)
    EhtGi = 21,
    /// EHT RU allocation, if not present then non-OFDMA was used (u8, see &enum nl80211_eht_ru_alloc)
    EhtRuAlloc = 22,
    /// S1G MCS index (u8, 0-10)
    S1gMcs = 23,
    /// S1G NSS value (u8, 1-4)
    S1gNss = 24,
    /// 1 MHz S1G rate
    MhzWidth1 = 25,
    /// 2 MHz S1G rate
    MhzWidth2 = 26,
    /// 4 MHz S1G rate
    MhzWidth4 = 27,
    /// 8 MHz S1G rate
    MhzWidth8 = 28,
    /// 16 MHz S1G rate
    MhzWidth16 = 29,
}
impl NlAttrType for Nl80211RateInfo {}

///
/// enum nl80211_band_attr - band attributes
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum Nl80211BandAttr {
    /// attribute number 0 is reserved
    Invalid = 0,
    /// supported frequencies in this band, an array of nested frequency attributes
    Frequencies = 1,
    /// supported bitrates in this band, an array of nested bitrate attributes
    Rates = 2,
    /// 16-byte attribute containing the MCS set as defined in 802.11n
    HtMcsSet = 3,
    /// HT capabilities, as in the HT information IE
    HtCapa = 4,
    /// A-MPDU factor, as in 11n
    HtAmpduFactor = 5,
    /// A-MPDU density, as in 11n,
    HtAmpduDensity = 6,
    /// 32-byte attribute containing the MCS set as defined in 802.11ac
    VhtMcsSet = 7,
    /// VHT capabilities, as in the HT information IE
    VhtCapa = 8,
    /// nested array attribute, with each entry using attributes from &enum nl80211_band_iftype_attr
    IfTypeData = 9,
    /// bitmap that indicates the 2.16 GHz channel(s) that are allowed to be used for EDMG transmissions.
    /// Defined by IEEE P802.11ay/D4.0 section 9.4.2.251.
    EdmgChannels = 10,
    /// Channel BW Configuration subfield encodes the allowed channel bandwidth configurations.
    /// Defined by IEEE P802.11ay/D4.0 section 9.4.2.251, Table 13.
    EdmgBwConfig = 11,
    /// S1G capabilities, supported S1G-MCS and NSS set subfield, as in the S1G information IE, 5 bytes
    S1gMcsNssSet = 12,
    /// S1G capabilities information subfield as in the S1G information IE, 10 bytes
    S1gCapa = 13,
}
impl NlAttrType for Nl80211BandAttr {}

///
/// enum nl80211_frequency_attr - frequency attributes
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum Nl80211FrequencyAttr {
    /// attribute number 0 is reserved
    Invalid = 0,
    /// Frequency in MHz
    Frequency = 1,
    /// Channel is disabled in current regulatory domain.
    Disabled = 2,
    /// no mechanisms that initiate radiation are permitted on this channel,
    /// this includes sending probe requests, or modes of operation that require beaconing.
    NoIr = 3,
    /// obsolete, same as _NO_IR
    NoIbss = 4,
    /// Radar detection is mandatory on this channel in current regulatory domain.
    Radar = 5,
    /// Maximum transmission power in mBm (100 * dBm).
    MaxTxPower = 6,
    /// current state for DFS (enum nl80211_dfs_state)
    OfsState = 7,
    /// time in milliseconds for how long this channel is in this DFS state.
    OfsTime = 8,
    /// HT40- isn't possible with this channel as the control channel
    NoHt40Minus = 9,
    /// HT40+ isn't possible with this channel as the control channel
    NoHt40Plus = 10,
    /// any 80 MHz channel using this channel as the primary or any of
    /// the secondary channels isn't possible, this includes 80+80 channels
    No80MHz = 11,
    /// any 160 MHz (but not 80+80) channel using this channel as the
    /// primary or any of the secondary channels isn't possible
    No160MHz = 12,
    /// DFS CAC time in milliseconds.
    DfsCacTime = 13,
    /// Only indoor use is permitted on this channel.
    /// A channel that has the INDOOR_ONLY attribute can only be
    /// used when there is a clear assessment that the device is operating in
    /// an indoor surroundings, i.e., it is connected to AC power (and not
    /// through portable DC inverters) or is under the control of a master
    /// that is acting as an AP and is connected to AC power.
    IndoorOnly = 14,
    /// IR operation is allowed on this
    /// channel if it's connected concurrently to a BSS on the same channel on
    /// the 2 GHz band or to a channel in the same UNII band (on the 5 GHz
    /// band), and IEEE80211_CHAN_RADAR is not set. Instantiating a GO or TDLS
    /// off-channel on a channel that has the IR_CONCURRENT attribute set can be
    /// done when there is a clear assessment that the device is operating under
    /// the guidance of an authorized master, i.e., setting up a GO or TDLS
    /// off-channel while the device is also connected to an AP with DFS and
    /// radar detection on the UNII band (it is up to user-space, i.e.,
    /// wpa_supplicant to perform the required verifications). Using this
    /// attribute for IR is disallowed for master interfaces (IBSS, AP).
    IrConcurrent = 15,
    /// 20 MHz operation is not allowed on this channel in current regulatory domain.
    No20MHz = 16,
    /// 10 MHz operation is not allowed on this channel in current regulatory domain.
    No10MHz = 17,
    /// this channel has wmm limitations.
    /// This is a nested attribute that contains the wmm limitation per AC.
    /// (see &enum nl80211_wmm_rule)
    Wmm = 18,
    /// HE operation is not allowed on this channel in current regulatory domain.
    NoHe = 19,
    /// frequency offset in KHz
    Offset = 20,
    /// 1 MHz operation is allowed on this channel in current regulatory domain.
    Allowed1MHz = 21,
    /// 2 MHz operation is allowed on this channel in current regulatory domain.
    Allowed2MHz = 22,
    /// 4 MHz operation is allowed on this channel in current regulatory domain.
    Allowed4MHz = 23,
    /// 8 MHz operation is allowed on this channel in current regulatory domain.
    Allowed8MHz = 24,
    /// 16 MHz operation is allowed on this channel in current regulatory domain.
    Allowed16MHz = 25,
    /// any 320 MHz channel using this channel as the primary or any of the secondary channels isn't possible
    No320MHz = 26,
    /// EHT operation is not allowed on this channel in current regulatory domain.
    NoEht = 27,
    /// Power spectral density (in dBm) that is allowed on this channel in current regulatory domain.
    Psd = 28,
    /// Operation on this channel is
    /// allowed for peer-to-peer or adhoc communication under the control
    /// of a DFS master which operates on the same channel (FCC-594280 D01
    /// Section B.3). Should be used together with %NL80211_RRF_DFS only.
    DfsConcurrent = 29,
    /// Client connection to VLP AP not allowed using this channel
    No6GHzVlpClient = 30,
    /// Client connection to AFC AP not allowed using this channel
    No6GHzAfcClient = 31,
    /// This channel can be used in monitor mode despite other (regulatory)
    /// restrictions, even if the channel is otherwise completely disabled.
    CanMonitor = 32,
    /// This channel can be used for a very low power (VLP) AP, despite being NO_IR.
    Allow6GHzVlpAp = 33,
    /// This channel can be active in 20 MHz bandwidth, despite being NO_IR.
    Allow20MHzActivity = 34,
    /// 4 MHz operation is not allowed on this channel in current regulatory domain.
    No4NHz = 35,
    /// 8 MHz operation is not allowed on this channel in current regulatory domain.
    No8NHz = 36,
    /// 16 MHz operation is not allowed on this channel in current regulatory domain.
    No16NHz = 37,
}
impl NlAttrType for Nl80211FrequencyAttr {}

///
/// enum nl80211_band - Frequency band
///
#[neli_enum(serialized_type = "u16")]
#[non_exhaustive]
pub enum Nl80211Band {
    /// 2.4 GHz ISM band
    Band2GHz = 0,
    /// around 5 GHz band (4.9 - 5.7 GHz)
    Band5GHz = 1,
    /// around 60 GHz band (58.32 - 69.12 GHz)
    Band60GHz = 2,
    /// around 6 GHz band (5.9 - 7.2 GHz)
    Band6GHz = 3,
    /// around 900MHz, supported by S1G PHYs
    BandS1GHz = 4,
    /// light communication band (placeholder)
    LC = 5,
}

///
/// enum nl80211_chan_width - channel width definitions
///
#[neli_enum(serialized_type = "u32")]
#[non_exhaustive]
pub enum Nl80211ChannelWidth {
    /// 20 MHz, non-HT channel
    Width20NoHt = 0,
    /// 20 MHz HT channel
    Width20 = 1,
    /// 40 MHz channel, the %NL80211_ATTR_CENTER_FREQ1 attribute must be provided as well
    Width40 = 2,
    /// 80 MHz channel, the %NL80211_ATTR_CENTER_FREQ1 attribute must be provided as well
    Width80 = 3,
    /// 80+80 MHz channel, the %NL80211_ATTR_CENTER_FREQ1
    /// and %NL80211_ATTR_CENTER_FREQ2 attributes must be provided as well
    Width80p80 = 4,
    /// 160 MHz channel, the %NL80211_ATTR_CENTER_FREQ1 attribute must be provided as well
    Width160 = 5,
    /// 5 MHz OFDM channel
    Width5 = 6,
    /// 10 MHz OFDM channel
    Width10 = 7,
    /// 1 MHz OFDM channel
    Width1 = 8,
    /// 2 MHz OFDM channel
    Width2 = 9,
    /// 4 MHz OFDM channel
    Width4 = 10,
    /// 8 MHz OFDM channel
    Width8 = 11,
    /// 16 MHz OFDM channel
    Width16 = 12,
    /// 320 MHz channel, the %NL80211_ATTR_CENTER_FREQ1 attribute must be provided as well
    Width320 = 13,
}
