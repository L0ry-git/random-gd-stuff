#![allow(dead_code)]

use libflate::gzip::{Decoder, Encoder};

use std::fmt::Display;
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::io::{Read, Write};
use std::path::Path;

use quick_xml::Reader;
use quick_xml::{events::Event, Writer};

type LevelEntry = (String, String);

const EMPTY_GAMESAVE_DEFAULT_DATA: [u8; 158] = [
    67, 63, 120, 66, 74, 74, 74, 74, 74, 74, 74, 74, 72, 60, 68, 115, 121, 51, 97, 69, 94, 88, 99,
    71, 71, 88, 121, 68, 113, 70, 38, 113, 93, 95, 71, 94, 70, 58, 72, 114, 127, 60, 70, 123, 114,
    70, 96, 120, 71, 96, 78, 93, 93, 94, 97, 91, 74, 125, 65, 127, 103, 82, 114, 74, 105, 79, 126,
    105, 103, 70, 113, 96, 78, 97, 126, 105, 105, 79, 120, 109, 67, 50, 50, 63, 74, 59, 70, 105,
    84, 92, 114, 108, 78, 66, 108, 109, 101, 58, 101, 120, 92, 77, 90, 78, 62, 123, 104, 100, 61,
    69, 125, 81, 61, 64, 109, 74, 93, 89, 102, 73, 89, 95, 91, 127, 97, 78, 58, 127, 50, 79, 69,
    73, 70, 102, 74, 97, 50, 70, 77, 92, 57, 90, 78, 74, 102, 66, 76, 73, 114, 63, 104, 74, 74, 74,
    74, 54, 11, 11,
];

const EMPTY_LEVEL_NAME: &str = "Unnamed 0";
const EMPTY_LEVEL_AUTHOR: &str = "LoryTheGamer";
const EMPTY_LEVEL_DESCRIPTION: &str = "!!! programz gnrated nivell !!!";
const EMPTY_LEVEL_ENTRIES: [(&str, &str); 7] = [
    ("k13", "1"),
    ("k21", "2"),
    ("k16", "1"),
    ("k50", "35"),
    ("kI1", "0"),
    ("kI2", "0"),
    ("kI3", "0"),
];

const IGNORE_KEYS: [&str; 10] = [
    "k36", "k85", "k86", "k87", "k88", "k19", "k89", "k71", "k90", "k34",
];

const DICT_START: &str = "LLM_01";
const DICT_END: &str = "LLM_02";
const LEVEL_DICT_HEADER: &str = "_isArr";

const LEVEL_DICT_START: &str = "k_";
const FINAL_LEVEL_KEY: &str = "kI6";
const LEVEL_HEADER: &str = "kCEK";

const LS_HEADER: &str = "H4sIAAAAAAAAC";
const LS_COLOR_CHANNEL_KEY: &str = "kS38";
const LS_OBJ_DELIMITER: &str = ";";
const LS_COLOR_CHANNEL_DELIMITER: &str = "|";
const LS_ENTRY_DELIMITER: &str = ",";
const LS_GROUP_ID_DELIMITER: &str = ".";

const IO_ERROR_MESSAGE: &str = "IO Error in LocalLevels file!";
const FILE_ERROR_MESSAGE: &str = "Error when creating file!";
const XML_READ_ERROR_MESSAGE: &str = "Error in XML reading!";
const XML_WRITE_ERROR_MESSAGE: &str = "Error in XML writing!";

const BASE64_DECODE_ERROR_MESSAGE: &str = "Error in Base64 decoding!";
const GZIP_DECODE_ERROR_MESSAGE: &str = "Error in GZIP decoding!";
const GZIP_ENCODE_ERROR_MESSAGE: &str = "Error in GZIP encoding!";

const LS_OBJ_KEY_ERROR: &str = "Error in object key! Unable to parse ";
const LS_OBJ_VALUE_ERROR: &str = "Error in object value! Unable to parse ";
const LS_BOOLEAN_PARSE_ERROR: &str = "Object is not a boolean string representation!";

pub struct LevelsGamesave<P: AsRef<Path>> {
    path: P,
    levels: Vec<GamesaveLevel>,
}

impl<P: AsRef<Path>> LevelsGamesave<P> {
    pub fn new(path: P) -> LevelsGamesave<P> {
        LevelsGamesave {
            path,
            levels: Vec::new(),
        }
    }

    fn xor_data(&self, data: Vec<u8>, key: u8) -> Vec<u8> {
        data.iter().map(|b| b ^ key).collect()
    }

    pub fn create_if_not_exists(&self) {
        if !self.path.as_ref().exists() {
            File::create(&self.path).unwrap_or_else(|err| {
                panic!("{} Error details: {:?}", FILE_ERROR_MESSAGE, err);
            });

            std::fs::write(&self.path, EMPTY_GAMESAVE_DEFAULT_DATA).expect(IO_ERROR_MESSAGE);
        }
    }

    pub fn decrypt_local_levels(&mut self) {
        let data = std::fs::read_to_string(self.path.as_ref()).expect(IO_ERROR_MESSAGE);

        let xor = self.xor_data(data.as_bytes().to_vec(), 11);
        let replaced = String::from_utf8(xor)
            .unwrap()
            .replace("-", "+")
            .replace("_", "/")
            .replace("\0", "");

        let base64_decoded = base64::decode(replaced.as_str())
            .unwrap_or_else(|err| panic!("{} Error type {:?}", BASE64_DECODE_ERROR_MESSAGE, err));
        let decoder = Decoder::new(&base64_decoded[..]).unwrap();

        let mut xml_reader = Reader::from_reader(BufReader::new(decoder));
        xml_reader.trim_text(true);

        let mut buf = Vec::new();
        let (mut data_temp, mut read_level) = (Vec::new(), false);

        loop {
            match xml_reader.read_event(&mut buf) {
                Ok(Event::Text(bt)) => {
                    let current = bt.unescape_and_decode(&xml_reader).unwrap();
                    let is_end = current.starts_with(DICT_END);
                    if current.starts_with(LEVEL_DICT_START) || is_end {
                        read_level = !is_end;
                        if !data_temp.is_empty() {
                            self.levels.push(GamesaveLevel::Unparsed(data_temp.clone()));
                            data_temp.clear();
                        }
                    } else if read_level {
                        let is_bool = match current.as_str() {
                            "k13" | "k47" => true,
                            _ => false,
                        };

                        data_temp.push(current);
                        if is_bool {
                            data_temp.push(String::from("1"))
                        };
                    }
                }
                Ok(Event::Eof) => break,
                Err(err) => {
                    panic!(
                        "{} Error type {:?}, position: {}",
                        XML_READ_ERROR_MESSAGE,
                        err,
                        xml_reader.buffer_position()
                    );
                }
                _ => (),
            }
            buf.clear();
        }
    }

    pub fn encrypt_local_levels(&self) {
        let data = self.to_string();
        let to_encode = data.as_bytes();

        let mut gzip_encoder = Encoder::new(Vec::new()).unwrap();
        match gzip_encoder.write_all(to_encode) {
            Err(err) => panic!("{} Error type {:?}", GZIP_ENCODE_ERROR_MESSAGE, err),
            _ => {}
        };
        let compressed = gzip_encoder.finish().into_result().unwrap();

        let base64_replaced = base64::encode(&compressed)
            .replace("+", "-")
            .replace("/", "_");
        let final_data = self.xor_data(base64_replaced.as_bytes().to_vec(), 11);
        std::fs::write(&self.path, final_data.clone()).expect(IO_ERROR_MESSAGE);
    }

    pub fn get_levels(&self) -> &Vec<GamesaveLevel> {
        &self.levels
    }

    pub fn get_levels_mut(&mut self) -> &mut Vec<GamesaveLevel> {
        &mut self.levels
    }

    pub fn get_parsed_levels(&mut self) -> Vec<&mut Level> {
        let mut ret = Vec::new();
        for level in self.levels.iter_mut() {
            match level {
                GamesaveLevel::Parsed(to_push) => ret.push(to_push),
                _ => {}
            }
        }

        ret
    }

    pub fn parse_level(&mut self, idx: usize) -> &mut Level {
        let mut_levels_ref = &mut self.levels[idx];
        let to_parse = match mut_levels_ref {
            GamesaveLevel::Unparsed(data) => data,
            GamesaveLevel::Parsed(level_ret) => return level_ret,
        };

        let mut temp_key = String::new();
        let mut entries: Vec<LevelEntry> = Vec::new();

        for curr in to_parse {
            if curr == FINAL_LEVEL_KEY {
                break;
            }
            let curr_value = curr.to_string();

            if curr.starts_with("k") {
                if !temp_key.is_empty() {
                    entries.push((curr_value, String::new()));
                    continue;
                }

                temp_key = curr_value;
            } else {
                entries.push((temp_key, curr_value));
                temp_key = String::new();
            }
        }
        *mut_levels_ref = GamesaveLevel::Parsed(Level::from(entries));
        match mut_levels_ref {
            GamesaveLevel::Parsed(level_ret) => return level_ret,
            _ => panic!(), //unreachable
        }
    }

    pub fn parse_all(&mut self) {
        for idx in 0..self.levels.len() {
            self.parse_level(idx);
        }
    }

    pub fn level_at(&self, idx: usize) -> Option<&Level> {
        match &self.levels[idx] {
            GamesaveLevel::Parsed(ret) => Some(ret),
            _ => None,
        }
    }

    pub fn level_at_mut(&mut self, idx: usize) -> Option<&mut Level> {
        match &mut self.levels[idx] {
            GamesaveLevel::Parsed(ret) => Some(ret),
            _ => None,
        }
    }

    pub fn count_levels(&self) -> usize {
        self.levels.len()
    }

    pub fn clear(&mut self) {
        self.levels.clear()
    }
}

#[derive(Debug)]
pub enum GamesaveLevel {
    Unparsed(Vec<String>),
    Parsed(Level),
}

pub(super) mod xml_write {

    use std::io::Cursor;

    use quick_xml::events::Event;
    use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText};
    use quick_xml::Writer;

    use super::{GamesaveLevel, Level};

    pub(crate) type XMLWriter = Writer<Cursor<Vec<u8>>>;

    const XML_VERSION: &str = "1.0";
    const PLIST_VERSION: &str = "1.0";
    const GJ_VERSION: &str = "2.0";

    const UNKNOWN_KEY_ERROR: &str = "Unknown key error! Unable to retrieve type for key ";
    const XML_BOOLEAN_IDENTIFIER: &str = "XML_BOOL";

    const STRING_TYPE: &str = "s";
    const INTEGER_TYPE: &str = "i";
    const R_INTEGER_TYPE: &str = "r";
    const DICT_TYPE: &str = "d";
    const BOOLEAN_TRUE: &str = "t /";

    const FOOTER_END: i32 = 12;

    impl GamesaveLevel {
        fn write_to_xml(&self, writer: &mut XMLWriter) -> quick_xml::Result<()> {
            match self {
                GamesaveLevel::Unparsed(vec_value) => {
                    let vec_iter = vec_value.iter();
                    let entries = vec_iter
                        .clone()
                        .step_by(2)
                        .zip(vec_iter.skip(1).step_by(2))
                        .collect::<Vec<(&String, &String)>>();

                    #[allow(non_snake_case)] //it's annoying shut up rust
                    let mut kI6_detected = false;
                    for (key, value) in entries {
                        if key == super::FINAL_LEVEL_KEY {
                            write_key(writer, key)?;

                            //write kI6 dict open
                            writer.write_event(Event::Start(BytesStart::owned_name(DICT_TYPE)))?;
                            write_key(writer, value)?;

                            kI6_detected = true;
                        } else if kI6_detected {
                            //hardcoded because this way it's efficient
                            write_value_with_type(writer, STRING_TYPE, key)?;
                            write_key(writer, value)?;
                        } else {
                            if super::IGNORE_KEYS.contains(&key.as_str()) {
                                continue;
                            };

                            write_normal_entry(
                                writer,
                                key,
                                GamesaveLevel::get_type(key),
                                value.as_str(),
                            )?;
                        }
                    }

                    //length of vec_value is always even, add last entry value to kI6 in order to not cut it
                    //<s>0</s>
                    write_value_with_type(writer, STRING_TYPE, "0")?;
                    //write kI6 dict close
                    writer.write_event(Event::End(BytesEnd::borrowed(DICT_TYPE.as_bytes())))?;
                }
                GamesaveLevel::Parsed(to_pack) => {
                    //write level data
                    GamesaveLevel::write_level_data(writer, to_pack)?;

                    //write all entries
                    for (key, value) in &to_pack.entries {
                        if super::IGNORE_KEYS.contains(&key.as_str()) {
                            continue;
                        };

                        let key = key.as_str();
                        write_normal_entry(
                            writer,
                            key,
                            GamesaveLevel::get_type(key),
                            value.as_str(),
                        )?;
                    }

                    //write footer dictionary
                    GamesaveLevel::write_footer_dictionary(writer)?;
                }
            };

            Ok(())
        }

        fn write_level_data(writer: &mut XMLWriter, to_pack: &Level) -> quick_xml::Result<()> {
            //write first entry: header
            write_key(writer, super::LEVEL_HEADER)?;
            write_value_with_type(writer, INTEGER_TYPE, "4")?;

            //write name
            write_key(writer, "k2")?;
            write_value_with_type(writer, STRING_TYPE, to_pack.name.as_str())?;

            //write description
            write_key(writer, "k3")?;
            write_value_with_type(
                writer,
                STRING_TYPE,
                to_pack.description.to_string().as_str(),
            )?;

            //write level string
            write_key(writer, "k4")?;
            write_value_with_type(
                writer,
                STRING_TYPE,
                to_pack.level_string.to_string().as_str(),
            )?;
            //write level author
            write_key(writer, "k5")?;
            write_value_with_type(writer, STRING_TYPE, to_pack.author.to_string().as_str())?;

            Ok(())
        }

        fn write_footer_dictionary(writer: &mut XMLWriter) -> quick_xml::Result<()> {
            //write kI6 key
            write_key(writer, super::FINAL_LEVEL_KEY)?;
            //write dict open
            writer.write_event(Event::Start(BytesStart::owned_name(DICT_TYPE)))?;

            //write footer
            for key in 0..(FOOTER_END + 1) {
                write_key(writer, key.to_string().as_str())?;
                write_value_with_type(writer, STRING_TYPE, "0")?;
            }

            //write dict close
            writer.write_event(Event::End(BytesEnd::borrowed(DICT_TYPE.as_bytes())))?;
            Ok(())
        }

        fn get_type<'a>(key: &str) -> &'a str {
            match key {
                super::LEVEL_HEADER | "k21" | "k16" | "k18" | "k48" | "k50" | "k80" => INTEGER_TYPE,
                "k2" | "k3" | "k4" | "k5" => STRING_TYPE,
                "k13" | "k47" => XML_BOOLEAN_IDENTIFIER,
                "kI1" | "kI2" | "kI3" => R_INTEGER_TYPE,
                _ => {
                    eprintln!("{} {}", UNKNOWN_KEY_ERROR, key);
                    "ERROR"
                }
            }
        }
    }

    pub fn write_on(writer: &mut XMLWriter, levels: &Vec<GamesaveLevel>) -> quick_xml::Result<()> {
        write_header_start(writer)?;
        write_dict(writer, levels)?;
        writer_header_end(writer)?;
        Ok(())
    }

    pub(crate) fn write_header_start(writer: &mut XMLWriter) -> quick_xml::Result<()> {
        let decl = BytesDecl::new(XML_VERSION.as_bytes(), None, None);
        writer.write_event(Event::Decl(decl))?;

        let mut plist = BytesStart::owned_name("plist");
        plist.push_attribute(("version", PLIST_VERSION));
        plist.push_attribute(("gjver", GJ_VERSION));
        writer.write_event(Event::Start(plist))?;

        Ok(())
    }
    fn write_dict(writer: &mut XMLWriter, levels: &Vec<GamesaveLevel>) -> quick_xml::Result<()> {
        writer.write_event(Event::Start(BytesStart::owned_name("dict")))?;

        //write levels
        write_key(writer, super::DICT_START)?;
        writer.write_event(Event::Start(BytesStart::owned_name(DICT_TYPE)))?;
        write_levels_dict(writer, levels)?;
        writer.write_event(Event::End(BytesEnd::borrowed(DICT_TYPE.as_bytes())))?;

        //write end part
        write_key(writer, super::DICT_END)?;
        write_value_with_type(writer, INTEGER_TYPE, "35")?;

        writer.write_event(Event::End(BytesEnd::borrowed(b"dict")))?;
        Ok(())
    }

    fn write_levels_dict(
        writer: &mut XMLWriter,
        levels: &Vec<GamesaveLevel>,
    ) -> quick_xml::Result<()> {
        write_key(writer, super::LEVEL_DICT_HEADER)?;
        writer.write_event(Event::Start(BytesStart::owned_name(BOOLEAN_TRUE)))?;

        for idx in 0..levels.len() {
            let level = &levels[idx];
            write_key(writer, format!("{}{}", "k_", idx).as_str())?;
            writer.write_event(Event::Start(BytesStart::owned_name(DICT_TYPE)))?;

            //write level
            level.write_to_xml(writer)?;
            writer.write_event(Event::End(BytesEnd::borrowed(DICT_TYPE.as_bytes())))?;
        }

        Ok(())
    }
    fn writer_header_end(writer: &mut XMLWriter) -> quick_xml::Result<()> {
        writer.write_event(Event::End(BytesEnd::borrowed(b"plist")))?;
        Ok(())
    }

    //util fns
    pub(crate) fn write_key(writer: &mut XMLWriter, key: &str) -> quick_xml::Result<()> {
        writer.write_event(Event::Start(BytesStart::owned_name("k")))?;
        writer.write_event(Event::Text(BytesText::from_plain_str(key)))?;
        writer.write_event(Event::End(BytesEnd::borrowed(b"k")))?;

        Ok(())
    }

    fn write_value_with_type(
        writer: &mut XMLWriter,
        value_type: &str,
        value: &str,
    ) -> quick_xml::Result<()> {
        writer.write_event(Event::Start(BytesStart::owned_name(value_type)))?;
        writer.write_event(Event::Text(BytesText::from_plain_str(
            value.to_string().as_str(),
        )))?;
        writer.write_event(Event::End(BytesEnd::borrowed(value_type.as_bytes())))?;

        Ok(())
    }

    pub(crate) fn write_normal_entry(
        writer: &mut XMLWriter,
        key: &str,
        value_type: &str,
        value: &str,
    ) -> quick_xml::Result<()> {
        //write the key
        write_key(writer, key)?;

        //if type is XML_BOOLEAN_IDENTIFIER write <t />, else write value
        match value_type {
            XML_BOOLEAN_IDENTIFIER => {
                writer.write_event(Event::Start(BytesStart::owned_name(BOOLEAN_TRUE)))?
            }
            _ => write_value_with_type(writer, value_type, value)?,
        };

        Ok(())
    }
}

impl<P: AsRef<Path>> Display for LevelsGamesave<P> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut xml_writer = Writer::new(Cursor::new(Vec::new()));
        xml_write::write_on(&mut xml_writer, &self.levels)
            .unwrap_or_else(|err| panic!("{} Error type {:?}", XML_WRITE_ERROR_MESSAGE, err));

        fmt.write_str(
            String::from_utf8(xml_writer.into_inner().into_inner())
                .unwrap()
                .as_str(),
        )
    }
}

#[derive(Debug)]
pub enum Base64Data<T> {
    Encoded(String),
    Decoded(T),
}

impl<T: Default> Default for Base64Data<T> {
    fn default() -> Self {
        Base64Data::Decoded(Default::default())
    }
}

const LEVEL_STRING_STRUCT_PATH: &str = "gd_lang::gamesave::LevelString";

impl<T: PrepareForEncryption> Display for Base64Data<T> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let result = match self {
            Base64Data::Encoded(encrypted_data) => encrypted_data.to_string(),
            Base64Data::Decoded(value) => {
                let mut result = base64::encode(&value.prepare_for_encryption()[..]);
                let is_level_string = std::any::type_name::<T>() == LEVEL_STRING_STRUCT_PATH;

                if is_level_string {
                    result = LS_HEADER.to_string()
                        + &(result.replace("+", "-").replace("/", "_"))[LS_HEADER.len()..];
                }

                result
            }
        };

        fmt.write_str(result.as_str())
    }
}

#[derive(Debug)]
pub struct Level {
    name: String,
    author: String,
    description: Base64Data<String>,
    level_string: Base64Data<LevelString>,
    entries: Vec<LevelEntry>,
}

impl Level {
    pub fn empty() -> Level {
        Level::new(
            EMPTY_LEVEL_NAME,
            EMPTY_LEVEL_AUTHOR,
            EMPTY_LEVEL_DESCRIPTION,
        )
    }

    pub fn new(name: &str, author: &str, description: &str) -> Level {
        Level {
            name: String::from(name),
            author: String::from(author),
            description: Base64Data::Decoded(String::from(description)),
            level_string: Base64Data::Decoded(LevelString {
                ..Default::default()
            }),
            entries: EMPTY_LEVEL_ENTRIES
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }
    }

    pub fn from(entries: Vec<LevelEntry>) -> Level {
        let mut ret = Level {
            ..Default::default()
        };

        let mut to_add_entries = Vec::new();
        for (key, value) in entries {
            match key.as_str() {
                LEVEL_HEADER => {}
                "k2" => ret.name = value,
                "k3" => ret.description = Base64Data::Encoded(value),
                "k4" => ret.level_string = Base64Data::Encoded(value),
                "k5" => ret.author = value,
                _ => to_add_entries.push((key, value)),
            }
        }
        ret.entries = to_add_entries;

        ret
    }

    pub fn decrypt_description(&mut self) {
        let desc_ref = &self.description;

        match desc_ref {
            Base64Data::Encoded(data) => {
                let decoded = base64::decode(data.as_str()).unwrap_or_else(|err| {
                    panic!("{} Error type {:?}", BASE64_DECODE_ERROR_MESSAGE, err)
                });
                self.description = Base64Data::Decoded(String::from_utf8(decoded).unwrap());
            }
            _ => {}
        }
    }

    pub fn decrypt_level_string(&mut self) {
        let str_ref = &self.level_string;

        match str_ref {
            Base64Data::Encoded(data) => {
                let mut data = data
                    .replace("-", "+")
                    .replace("_", "/")
                    .replace("\0", "")
                    .as_bytes()
                    .to_vec();
                while data.len() % 4 != 0 {
                    data.push(b'=')
                }

                let base64_decoded = base64::decode(String::from_utf8(data).unwrap().as_str())
                    .unwrap_or_else(|err| {
                        panic!("{} Error type {:?}", BASE64_DECODE_ERROR_MESSAGE, err)
                    });
                let mut ls_decoder = Decoder::new(&base64_decoded[..]).unwrap();
                let mut decoded = Vec::new();
                match ls_decoder.read_to_end(&mut decoded) {
                    Err(err) => panic!("{} Error type {:?}", GZIP_DECODE_ERROR_MESSAGE, err),
                    _ => {}
                };

                let decrypted_ls = LevelString::from(String::from_utf8(decoded).unwrap());
                self.level_string = Base64Data::Decoded(decrypted_ls);
            }
            _ => {}
        }
    }

    pub fn get_ls_if_parsed(&self) -> Option<&LevelString> {
        match &self.level_string {
            Base64Data::Decoded(ret) => Some(ret),
            _ => None,
        }
    }

    pub fn get_ls_if_parsed_mut(&mut self) -> Option<&mut LevelString> {
        match &mut self.level_string {
            Base64Data::Decoded(ret) => Some(ret),
            _ => None,
        }
    }

    pub fn get_description_if_parsed(&self) -> Option<&String> {
        match &self.description {
            Base64Data::Decoded(ret) => Some(ret),
            _ => None,
        }
    }

    pub fn get_description_if_parsed_mut(&mut self) -> Option<&mut String> {
        match &mut self.description {
            Base64Data::Decoded(ret) => Some(ret),
            _ => None,
        }
    }

    pub fn name(&self) -> &String {
        &self.name
    }

    pub fn name_mut(&mut self) -> &mut String {
        &mut self.name
    }

    pub fn author(&self) -> &String {
        &self.author
    }

    pub fn additional_entries(&self) -> &Vec<LevelEntry> {
        &self.entries
    }

    pub fn additional_entries_mut(&mut self) -> &mut Vec<LevelEntry> {
        &mut self.entries
    }
}

impl Default for Level {
    fn default() -> Level {
        Level::empty()
    }
}

pub trait PrepareForEncryption {
    fn prepare_for_encryption(&self) -> Vec<u8>;
}

#[derive(Default, Debug)]
pub struct LevelString {
    //level string data
    color_channels: Vec<String>,
    entries: Vec<LevelEntry>,
    level_objects: Vec<LevelObject>,
}

impl LevelString {
    pub fn from(mut ls_data: String) -> LevelString {
        if ls_data.ends_with(LS_OBJ_DELIMITER) {
            ls_data.pop();
        }
        let mut split_ls = ls_data.split(LS_OBJ_DELIMITER);

        let header = split_ls.next().unwrap().to_string();
        let header_split_iter = header.split(LS_ENTRY_DELIMITER);

        let entries = header_split_iter
            .clone()
            .step_by(2)
            .zip(header_split_iter.skip(1).step_by(2));

        let init_entry_iter = entries.clone();
        let mut skip = 0;

        let mut color_channels = Vec::new();
        let mut level_objects = Vec::new();

        for (key, value) in entries {
            //level entries
            skip += 1;

            match key {
                LS_COLOR_CHANNEL_KEY => {
                    //color channels
                    let mut to_split = value.to_string();
                    to_split.pop();

                    color_channels = to_split
                        .split(LS_COLOR_CHANNEL_DELIMITER)
                        .map(|sl| sl.to_string())
                        .collect();
                    break;
                }
                _ => {}
            }
        }
        for obj in split_ls {
            //level objects
            level_objects.push(LevelObject::from(obj.to_string()));
        }

        LevelString {
            color_channels,
            entries: init_entry_iter
                .skip(skip)
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            level_objects,
        }
    }

    pub fn level_objects(&mut self) -> &mut Vec<LevelObject> {
        &mut self.level_objects
    }
}

impl Display for LevelString {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut data = LS_COLOR_CHANNEL_KEY.to_string() + LS_ENTRY_DELIMITER;
        data.push_str(
            self.color_channels
                .join(LS_COLOR_CHANNEL_DELIMITER)
                .as_str(),
        );
        data.push_str(LS_COLOR_CHANNEL_DELIMITER);
        data.push_str(LS_ENTRY_DELIMITER);

        data.push_str(
            self.entries
                .iter()
                .fold(Vec::new(), |mut ret, (key, value)| {
                    let mut to_push: String = String::from(key.as_str());
                    to_push.push_str(LS_ENTRY_DELIMITER);
                    to_push.push_str(value.as_str());

                    ret.push(to_push);
                    ret
                })
                .join(LS_ENTRY_DELIMITER)
                .as_str(),
        );

        data.push_str(LS_OBJ_DELIMITER);
        data.push_str(
            self.level_objects
                .iter()
                .map(|obj| obj.to_string())
                .collect::<Vec<String>>()
                .join(LS_OBJ_DELIMITER)
                .as_str(),
        );
        data.push_str(LS_OBJ_DELIMITER);

        fmt.write_str(data.as_str())
    }
}

impl PrepareForEncryption for LevelString {
    fn prepare_for_encryption(&self) -> Vec<u8> {
        let to_encode = self.to_string();
        let mut ls_encoder = Encoder::new(Vec::new()).unwrap();
        match ls_encoder.write_all(to_encode.as_bytes()) {
            Err(err) => panic!("{} Error type {:?}", GZIP_ENCODE_ERROR_MESSAGE, err),
            _ => {}
        };
        ls_encoder.finish().into_result().unwrap()
    }
}

impl PrepareForEncryption for String {
    fn prepare_for_encryption(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
}

pub type LevelObjectKey = usize;
pub type LevelObjectMap = BTreeMap<LevelObjectKey, LevelObjectValue>;

#[derive(Debug)]
pub enum LevelObjectValue {
    Integer(i16),
    Float(f32),
    GroupIDs(Vec<i16>),
    String(String),
    Boolean(bool),
}

impl Display for LevelObjectValue {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            LevelObjectValue::Integer(i_value) => i_value.to_string(),
            LevelObjectValue::Float(f_value) => f_value.to_string(),
            LevelObjectValue::GroupIDs(groups_value) => groups_value
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<String>>()
                .join(LS_GROUP_ID_DELIMITER),
            LevelObjectValue::String(s_value) => s_value.to_owned(),
            LevelObjectValue::Boolean(b_value) => String::from(if *b_value { "1" } else { "0" }),
        };

        fmt.write_str(str.as_str())
    }
}

pub enum SpecialColorID {
    Background = 1000,
    Ground = 1001,
    Line = 1002,
    Line3D = 1003,
    Object = 1004,
    CopyPlayerColor1 = 1005,
    CopyPlayerColor2 = 1006,
    LightBackground = 1007,
    Ground2 = 1009,
    Black = 1010,
    White = 1011,
    Lighter = 1012,
}

use std::collections::BTreeMap;

const EMPTY_LEVELOBJ_ID: i16 = 1;
const EMPTY_LEVELOBJ_POS: (f32, f32) = (0.0, 0.0);
const EMPTY_LEVELOBJ_COLOR_ID: i16 = SpecialColorID::Object as i16;

#[derive(Debug)]
pub struct LevelObject {
    properties: LevelObjectMap,
}

impl LevelObject {
    pub fn empty() -> LevelObject {
        LevelObject::new(
            EMPTY_LEVELOBJ_ID,
            EMPTY_LEVELOBJ_POS,
            EMPTY_LEVELOBJ_COLOR_ID,
            vec![],
        )
    }

    pub fn new(object_id: i16, pos: (f32, f32), color_id: i16, group_ids: Vec<i16>) -> LevelObject {
        let (x, y) = pos;

        //create entries map
        let mut map: LevelObjectMap = vec![
            (1, LevelObjectValue::Integer(object_id)),
            (2, LevelObjectValue::Float(x)),
            (3, LevelObjectValue::Float(y)),
            (21, LevelObjectValue::Integer(color_id)),
        ]
        .into_iter()
        .collect();

        if !group_ids.is_empty() {
            map.insert(57, LevelObjectValue::GroupIDs(group_ids));
        }

        LevelObject { properties: map }
    }

    pub fn from(object_string: String) -> LevelObject {
        let split_iter = object_string.split(LS_ENTRY_DELIMITER);

        let map: LevelObjectMap = split_iter
            .clone()
            .step_by(2)
            .zip(split_iter.skip(1).step_by(2))
            .fold(BTreeMap::new(), |mut ret, (key, value)| {
                let parsed_key: LevelObjectKey;

                match key.parse() {
                    Ok(value_ok) => parsed_key = value_ok,
                    Err(err) => {
                        eprintln!("{} {}! Error: {:?}", LS_OBJ_KEY_ERROR, key, err);
                        return ret;
                    }
                }

                match LevelObject::parse_from_key(&mut ret, parsed_key, value) {
                    Err(err) => {
                        eprintln!("{} {}! Error: {:?}", LS_OBJ_VALUE_ERROR, key, err);
                    }
                    _ => {}
                }
                ret
            });

        LevelObject { properties: map }
    }

    fn parse_from_key(
        map: &mut LevelObjectMap,
        parsed_key: LevelObjectKey,
        value: &str,
    ) -> Result<(), String> {
        match parsed_key {
            //integer key
            1 | 20 | 21 | 22 | 24 | 25 | 61 | 180 => match value.parse::<i16>() {
                Ok(parsed_value) => {
                    map.insert(parsed_key, LevelObjectValue::Integer(parsed_value));
                }
                Err(err) => return Err(err.to_string()),
            },
            //float key
            2 | 3 | 6 | 32 => match value.parse::<f32>() {
                Ok(parsed_value) => {
                    map.insert(parsed_key, LevelObjectValue::Float(parsed_value));
                }
                Err(err) => return Err(err.to_string()),
            },
            //integer array (group id array)
            57 => {
                let mut to_insert = Vec::new();

                for group in value.split(".") {
                    match group.parse::<i16>() {
                        Ok(parsed_group) => to_insert.push(parsed_group),
                        Err(err) => return Err(err.to_string()),
                    }
                }

                map.insert(parsed_key, LevelObjectValue::GroupIDs(to_insert));
            }
            //string
            43 | 44 => {
                map.insert(parsed_key, LevelObjectValue::String(value.to_string()));
            }
            //bool
            4 | 5 | 34 | 41 | 42 | 64 | 67 | 96 | 103 => {
                match value {
                    "1" => map.insert(parsed_key, LevelObjectValue::Boolean(true)),
                    "0" => map.insert(parsed_key, LevelObjectValue::Boolean(false)),
                    _ => return Err(String::from(LS_BOOLEAN_PARSE_ERROR)),
                };
            }
            _ => {}
        }

        Ok(())
    }

    pub fn properties(&self) -> &LevelObjectMap {
        &self.properties
    }

    pub fn properties_mut(&mut self) -> &mut LevelObjectMap {
        &mut self.properties
    }
}

impl Display for LevelObject {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = self
            .properties()
            .iter()
            .fold(String::new(), |mut ret, (key, value)| {
                ret.push_str(key.to_string().as_str());
                ret.push_str(LS_ENTRY_DELIMITER);
                ret.push_str(value.to_string().as_str());
                ret.push_str(LS_ENTRY_DELIMITER);

                ret
            });

        result.pop();
        fmt.write_str(result.as_str())
    }
}

impl Default for LevelObject {
    fn default() -> Self {
        LevelObject::empty()
    }
}
