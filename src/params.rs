// (* c is a constant factor on vrf-win likelihood *)
// (* c = 2^0 is production behavior *)
// (* c > 2^0 is a temporary hack for testnets *)
pub const C: i32 = 1;

// (* f determines the fraction of slots that will have blocks if c = 2^0 *)
pub const F: f32 = 3_f32 / 4_f32;
