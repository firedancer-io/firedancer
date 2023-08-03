use std::ffi::{
  c_char,
  CString,
};

pub struct GlobalAddress {
  gaddr: CString,
  _offset: u64,
}

impl GlobalAddress {
  pub(crate) fn as_ptr(&self) -> *const c_char {
      self.gaddr.as_ptr()
  }
}

impl TryFrom<String> for GlobalAddress {
  type Error = ();

  fn try_from(value: String) -> Result<Self, Self::Error> {
      let (_workspace, offset) = match value.split_once(':') {
          None => return Err(()),
          Some(parts) => parts,
      };

      let offset = match offset.parse() {
          Err(_) => return Err(()),
          Ok(offset) => offset,
      };

      let gaddr = match CString::new(value) {
          Err(_) => return Err(()),
          Ok(path) => path,
      };

      Ok(GlobalAddress {
          gaddr,
          _offset: offset,
      })
  }
}
