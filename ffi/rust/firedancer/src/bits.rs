macro_rules! align_up {
  ( $x:expr, $a:expr ) => {
      ($x + ($a - 1)) & !($a - 1)
  };
}

macro_rules! layout {
  ( value=$value:expr, ) => { $value };
  ( value=$value:expr, ($align:expr, $size:expr), $($tail:tt)*) => {
      layout!( value=align_up!($value, $align) + $size, $($tail)*)
  };
  ( align=$align:expr, [ $($tail:tt)* ]) => {
      align_up!(layout!(value = 0, $($tail)*), $align)
  };
}

pub(crate) use {
  align_up,
  layout,
};

#[cfg(test)]
mod tests {
  #[test]
  fn test_align_up() {
      let zeros = 0u64;
      let ones = u64::MAX;

      for i in 0..64 {
          let align = 1u64 << i;
          let lo = (1u64 << i) - 1;
          let hi = !lo;

          assert_eq!(align_up!(zeros, align), zeros);
          assert_eq!(align_up!(ones, align), if i == 0 { ones } else { zeros });
          for j in 0..64 {
              let x = 1u64 << j;
              assert_eq!(align_up!(x, align), (x + lo) & hi);
          }
      }
  }
}
