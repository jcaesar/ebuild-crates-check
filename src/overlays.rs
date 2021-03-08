use serde::Deserialize;
#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Quality {
    Experimental,
    Testing,
    Stable,
    Core,
}
#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Official,
    Unofficial,
}
#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnerType {
    Person,
    Project,
}
#[derive(Debug, Eq, PartialEq, Deserialize)]
pub struct Owner {
    #[serde(rename = "type")]
    typ: OwnerType,
    pub name: Option<String>,
    pub email: String,
}
#[derive(Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    Git,
    Rsync,
    Mercurial,
    Svn,
}
#[derive(Debug, Eq, PartialEq, Deserialize)]
pub struct Source {
    #[serde(rename = "type")]
    pub typ: SourceType,
    #[serde(rename = "$value")]
    pub url: String,
}
#[derive(Debug, Eq, PartialEq, Deserialize)]
pub struct Overlay {
    pub quality: Quality,
    pub status: Status,
    pub name: String,
    // Ignored: description
    pub homepage: Option<String>,
    #[serde(rename = "owner")]
    pub owners: Vec<Owner>,
    #[serde(rename = "source")]
    pub sources: Vec<Source>,
}

#[derive(Debug, Eq, PartialEq, Deserialize)]
pub struct Meta {
    #[serde(default)]
    repo: Vec<Overlay>,
}

pub fn parse(content: &[u8]) -> anyhow::Result<Vec<Overlay>> {
    let ret = quick_xml::de::from_reader::<_, Meta>(std::io::Cursor::new(content))?.repo;
    log::trace!("{:#?} - {} entries", ret, ret.len());
    Ok(ret)
}

#[cfg(test)]
mod test {
    use super::OwnerType::*;
    use super::Quality::*;
    use super::SourceType::*;
    use super::Status::*;
    use super::*;

    #[test]
    fn parse_ex() {
        let expect = vec![Overlay {
            quality: Core,
            status: Official,
            name: "gentoo".to_string(),
            homepage: Some("https://gentoo.org/".to_string()),
            owners: vec![Owner {
                typ: Project,
                name: None,
                email: "bug-wranglers@gentoo.org".to_string(),
            }],
            sources: vec![
                Source {
                    typ: Rsync,
                    url: "rsync://rsync.gentoo.org/gentoo-portage".to_string(),
                },
                Source {
                    typ: Git,
                    url: "https://anongit.gentoo.org/git/repo/gentoo.git".to_string(),
                },
            ],
        }];
        assert_eq!(
            expect,
            parse(include_bytes!("tests/repos-example.xml")).unwrap()
        );
    }
}
