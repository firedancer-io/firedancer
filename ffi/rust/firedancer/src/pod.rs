use std::ffi::{
  c_char,
  CStr,
  CString, c_void,
};
use std::marker::PhantomData;
use std::ptr::{null, NonNull};
use std::sync::Arc;

use firedancer_sys::*;
use paste::paste;

use crate::*;

#[derive(Clone)]
pub struct Pod {
  laddr: *const u8,
  workspace: Arc<Workspace>,
}

unsafe impl Send for Pod {}
unsafe impl Sync for Pod {}

impl Drop for Pod {
  fn drop(&mut self) {
      unsafe { util::fd_pod_leave(self.laddr) };
  }
}

impl Pod {
  pub unsafe fn join<T: TryInto<GlobalAddress>>(gaddr: T) -> Result<Self, ()> {
      let workspace = Workspace::map(gaddr)?;
      let laddr = util::fd_pod_join(workspace.laddr.as_ptr());
      if laddr.is_null() {
          Err(())
      } else {
          Ok(Self {
              laddr,
              workspace: Arc::new(workspace),
          })
      }
  }

  pub unsafe fn join_default<T: AsRef<str>>(wksp: T) -> Result<Self, ()> {
      let wksp_str = CString::new(wksp.as_ref()).unwrap();
      let wksp = util::fd_wksp_attach(wksp_str.as_ptr());
      if wksp.is_null() {
          return Err(());
      }

      let pod = util::fd_wksp_laddr( wksp, (*wksp).gaddr_lo );
      if pod.is_null() {
          return Err(());
      }

      let laddr = util::fd_pod_join(pod);

      if laddr.is_null() {
          Err(())
      } else {
          Ok(Self {
              laddr,
              workspace: Arc::new(Workspace {
                  laddr: NonNull::new(laddr as *mut c_void).unwrap(),
                  _marker: PhantomData,
              }),
          })
      }
  }

  pub fn try_query<T: FromPod, S: AsRef<str>>(&self, key: S) -> Option<T> {
      let key = match CString::new(key.as_ref()) {
          Ok(key) => key,
          _ => return None,
      };

      T::try_query(self, key.as_ptr())
  }

  pub fn query<T: FromPod + Default, S: AsRef<str>>(&self, key: S) -> T {
      let key = match CString::new(key.as_ref()) {
          Ok(key) => key,
          _ => return T::default(),
      };

      T::query(self, key.as_ptr())
  }
}

pub trait FromPod: Sized {
  fn try_query(pod: &Pod, key: *const c_char) -> Option<Self>;

  fn query(pod: &Pod, key: *const c_char) -> Self {
      FromPod::try_query(pod, key).unwrap()
  }
}

impl FromPod for String {
  fn try_query(pod: &Pod, key: *const c_char) -> Option<Self> {
      let value = unsafe { util::fd_pod_query_cstr(pod.laddr, key, null()) } as *const i8;

      if value.is_null() {
          return None;
      }

      match unsafe { CStr::from_ptr(value).to_str() } {
          Ok(str) => Some(str.to_owned()),
          _ => None,
      }
  }
}

impl FromPod for Pod {
  fn try_query(pod: &Pod, key: *const c_char) -> Option<Self> {
      let laddr = unsafe { util::fd_pod_query_subpod(pod.laddr, key) };

      if laddr.is_null() {
          return None;
      }

      Some(Pod {
          laddr,
          workspace: pod.workspace.clone(),
      })
  }
}

impl FromPod for GlobalAddress {
  fn try_query(pod: &Pod, key: *const c_char) -> Option<Self> {
      let string: String = FromPod::try_query(pod, key)?;
      string.try_into().ok()
  }
}

macro_rules! impl_from_pod {
  ($ty:ty, $id:ident) => {
      impl FromPod for $ty {
          fn try_query(pod: &Pod, key: *const c_char) -> Option<Self> {
              paste! {
                  unsafe {
                      Some(util::[<fd_pod_query_ $id>](pod.laddr, key, $ty::default()))
                  }
              }
          }
      }
  };
}

impl_from_pod!(i8, char);
impl_from_pod!(i16, short);
impl_from_pod!(i32, int);
impl_from_pod!(i64, long);
impl_from_pod!(u8, uchar);
impl_from_pod!(u16, ushort);
impl_from_pod!(u32, uint);
impl_from_pod!(u64, ulong);
