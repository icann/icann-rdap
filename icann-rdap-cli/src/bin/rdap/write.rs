use std::io::ErrorKind;

use minus::Pager;

#[derive(Clone)]
pub(crate) struct FmtWrite<W: std::fmt::Write>(pub(crate) W);

impl<W: std::fmt::Write> std::io::Write for FmtWrite<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .write_str(&String::from_utf8_lossy(buf))
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct PagerWrite(pub(crate) Pager);

impl std::io::Write for PagerWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .push_str(String::from_utf8_lossy(buf))
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
