extern "c" fn abs(x: c_int) c_int;

pub fn add(a: i32, b: i32) i32 {
    const c = abs(b);
    return a + c;
}
