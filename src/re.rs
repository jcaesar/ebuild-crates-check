use regex::{Regex, RegexBuilder};
lazy_static::lazy_static! {
    pub static ref CRATES: Regex = RegexBuilder::new("\\n *CRATES=\"(.*?)\" *(#.*)?\n").dot_matches_new_line(true).build().unwrap();
    pub static ref DEPSPEC: Regex = Regex::new(r"^([a-zA-Z0-9_\-]+)-([0-9]+\.[0-9]+\.[0-9]+.*)$").unwrap();
    pub static ref USES_CARGO_ECLASS: Regex = Regex::new(r"\n[ \t]*inherit.*?cargo").unwrap();

    // Based on site-packages/portage/versions.py... meh, complicated
    pub static ref EBUILD_DOTS:  Regex = Regex::new(r"/(?P<pn>[\w+][\w+.-]*?(?P<pn_inval>-(-r(\d+))?)?)-(?P<ver>(\d+)((\.\d+)*)([a-z]?)((_(pre|p|beta|alpha|rc)\d*)*))(-r(?P<rev>\d+))?\.ebuild$").unwrap();
}

pub fn split_pkgver(path: &str) -> Option<(&str, &str)> {
    EBUILD_DOTS.captures(path).map(|capt| (
        capt.name("pn").unwrap().as_str(),
        capt.name("ver").unwrap().as_str(),
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn crates() {
        let test = include_str!("tests/example.ebuild");
        assert_eq!(
            "\nadler32-1.0.4\narrayref-0.3.6\nxattr-0.2.2\n",
            &CRATES.captures(test).expect("matches")[1]
        );
    }

    #[test]
    fn depspec() {
        let capt = DEPSPEC
            .captures("clap-clap32-clap-3.0.0-beta.2")
            .expect("matches");
        assert_eq!("clap-clap32-clap", &capt[1]);
        assert_eq!("3.0.0-beta.2", &capt[2]);
    }

    #[test]
    fn eclass() {
        let test = include_str!("tests/example.ebuild");
        assert!(USES_CARGO_ECLASS.is_match(test));
        // negative test?
    }

    #[test]
    fn ebuild() {
        assert_eq!(
            Some(("gitui", "0.12.0")),
            split_pkgver("dev-vcs/gitui/gitui-0.12.0.ebuild")
        )
    }
}
