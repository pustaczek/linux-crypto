use std::ffi::c_void;
use std::io;
use std::io::Read;
use std::io::Write;

pub struct Algorithm {
    address: libc::sockaddr_alg,
}

pub struct Context {
    fd: i32,
}

pub struct Operation {
    fd: i32,
}

impl Algorithm {
    pub const fn new(salg_type: &[u8], salg_name: &[u8]) -> Algorithm {
        Algorithm {
            address: libc::sockaddr_alg {
                salg_family: libc::AF_ALG as u16,
                salg_type: pad_salg(salg_type),
                salg_feat: 0,
                salg_mask: 0,
                salg_name: pad_salg(salg_name),
            },
        }
    }
}

impl Context {
    pub fn new(algorithm: &Algorithm) -> io::Result<Context> {
        let mut context = Context::new_unbound()?;
        context.bind(algorithm)?;
        Ok(context)
    }

    fn new_unbound() -> io::Result<Context> {
        let fd = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Context { fd })
        }
    }

    fn bind(&mut self, algorithm: &Algorithm) -> io::Result<()> {
        let address_ptr = &algorithm.address as *const libc::sockaddr_alg as *const libc::sockaddr;
        let address_len = std::mem::size_of_val(&algorithm.address) as u32;
        let ret = unsafe { libc::bind(self.fd, address_ptr, address_len) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn set_key(&mut self, key: &[u8]) -> io::Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_ALG,
                libc::ALG_SET_KEY,
                key.as_ptr() as *const c_void,
                key.len() as u32,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn start(&self) -> io::Result<Operation> {
        let fd = unsafe { libc::accept(self.fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Operation { fd })
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl Write for Operation {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let sent = unsafe {
            libc::send(
                self.fd,
                buf.as_ptr() as *const c_void,
                buf.len(),
                libc::MSG_MORE,
            )
        };
        if sent >= 0 {
            Ok(sent as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for Operation {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let sent = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if sent >= 0 {
            Ok(sent as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

pub const fn pad_salg<const N: usize>(text: &[u8]) -> [u8; N] {
    let mut array = [0; N];
    let mut i = 0;
    while i < text.len() {
        array[i] = text[i];
        i += 1;
    }
    array
}
