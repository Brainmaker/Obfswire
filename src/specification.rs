//! The informal specification of the ObfsWire protocol.

// Stream initial frame:
// ```text
// | salt | tag | reserved | direction | stream_id | timestamp | body_len | payload_len |     ...    |
// |  32B | 16B |    1B    |     1B    |     8B    |     8B    |    2B    |     2B      |            |
// |                                    <- header ->                                    | <- body -> |
// |                                          <- init_frame ->                                       |
//
// |        ...         | tag | payload  | padding  |
// |                    | 16B | variable | variable |
// |    <- header ->    |        <- body ->         |
// |                 <- init_frame ->               |
// ```
pub(crate) const INIT_FRAME_MAX_LEN: usize = 8192;
#[allow(unused)]
pub(crate) const INIT_FRAME_MIN_LEN: usize = INIT_HDR_LEN + INIT_BODY_MIN_LEN;
pub(crate) const INIT_HDR_LEN: usize = 32 + 16 + 1 + 1 + 8 + 8 + 2 + 2; // 70
pub(crate) const INIT_BODY_MAX_LEN: usize = INIT_FRAME_MAX_LEN - INIT_HDR_LEN;
pub(crate) const INIT_BODY_MIN_LEN: usize = INIT_PAYLOAD_MIN_LEN + INIT_TAG_LEN;
pub(crate) const INIT_SALT_LEN: usize = 32;
pub(crate) const INIT_PAYLOAD_MAX_LEN: usize = INIT_BODY_MAX_LEN - INIT_TAG_LEN;
pub(crate) const INIT_PAYLOAD_MIN_LEN: usize = 0;
#[allow(unused)]
pub(crate) const INIT_PAD_MAX_LEN: usize = INIT_PAYLOAD_MAX_LEN;
#[allow(unused)]
pub(crate) const INIT_PAD_MIN_LEN: usize = INIT_PAYLOAD_MIN_LEN;
pub(crate) const INIT_TAG_LEN: usize = 16;

// Stream frame:
// ```text
// | tag | command | body_len | payload_len | tag | payload  | padding  |
// | 16B |    1B   |    2B    |     2B      | 16B | variable | variable |
// |              <- header ->              |         <- body ->        |
// |                           <- frame ->                              |
//
// ```
pub(crate) const FRAME_MAX_LEN: usize = 65535;
pub(crate) const FRAME_MIN_LEN: usize = HDR_LEN + BODY_MIN_LEN;
pub(crate) const HDR_LEN: usize = 16 + 2 + 2 + 1; // 21
pub(crate) const BODY_MAX_LEN: usize = FRAME_MAX_LEN - HDR_LEN;
pub(crate) const BODY_MIN_LEN: usize = PAYLOAD_MIN_LEN + TAG_LEN;
pub(crate) const PAYLOAD_MAX_LEN: usize = BODY_MAX_LEN - TAG_LEN;
pub(crate) const PAYLOAD_MIN_LEN: usize = 0;
#[allow(unused)]
pub(crate) const PADDING_MAX_LEN: usize = PAYLOAD_MAX_LEN;
#[allow(unused)]
pub(crate) const PADDING_MIN_LEN: usize = PAYLOAD_MIN_LEN;
pub(crate) const TAG_LEN: usize = 16;
