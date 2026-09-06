// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Validates numbers as Serde emits them to the canonical JSON serializer.
//! Wraps compound values recursively without serializing the input twice.

use crate::format::number::{validate_integer, FLOAT_ERROR};
use serde::ser::{self, Serialize, Serializer};

pub(super) struct IntegerOnly<T>(T, NumberMode);

#[derive(Clone, Copy)]
enum NumberMode {
    Value,
    Key,
}

impl<T> IntegerOnly<T> {
    pub(super) fn new(value: T) -> Self {
        Self(value, NumberMode::Value)
    }
}

impl<T: Serialize> Serialize for IntegerOnly<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(IntegerSerializer(serializer, self.1))
    }
}

struct IntegerSerializer<S>(S, NumberMode);
struct Compound<S>(S);

impl<S: Serializer> IntegerSerializer<S> {
    fn serialize_float<T: Serialize>(self, value: T, finite: bool) -> Result<S::Ok, S::Error> {
        if matches!(self.1, NumberMode::Key) && finite {
            let key = serde_json::to_string(&value).map_err(ser::Error::custom)?;
            self.0.serialize_str(&key)
        } else {
            Err(ser::Error::custom(FLOAT_ERROR))
        }
    }
}

macro_rules! forward_scalar {
    ($($method:ident($($arg:ident: $ty:ty),*));* $(;)?) => {
        $(fn $method(self, $($arg: $ty),*) -> Result<Self::Ok, Self::Error> {
            self.0.$method($($arg),*)
        })*
    };
}

macro_rules! integer_scalar {
    ($($method:ident($ty:ty));* $(;)?) => {
        $(fn $method(self, value: $ty) -> Result<Self::Ok, Self::Error> {
            if matches!(self.1, NumberMode::Key) {
                return self.0.serialize_str(&value.to_string());
            }
            validate_integer(i128::from(value)).map_err(ser::Error::custom)?;
            self.0.$method(value)
        })*
    };
}

macro_rules! compound_start {
    ($($method:ident($($arg:ident: $ty:ty),*) -> $output:ident);* $(;)?) => {
        $(fn $method(self, $($arg: $ty),*) -> Result<Self::$output, Self::Error> {
            self.0.$method($($arg),*).map(Compound)
        })*
    };
}

impl<S: Serializer> Serializer for IntegerSerializer<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = Compound<S::SerializeSeq>;
    type SerializeTuple = Compound<S::SerializeTuple>;
    type SerializeTupleStruct = Compound<S::SerializeTupleStruct>;
    type SerializeTupleVariant = Compound<S::SerializeTupleVariant>;
    type SerializeMap = Compound<S::SerializeMap>;
    type SerializeStruct = Compound<S::SerializeStruct>;
    type SerializeStructVariant = Compound<S::SerializeStructVariant>;

    forward_scalar! {
        serialize_bool(value: bool);
        serialize_char(value: char);
        serialize_str(value: &str);
        serialize_bytes(value: &[u8]);
        serialize_none();
        serialize_unit();
        serialize_unit_struct(name: &'static str);
        serialize_unit_variant(name: &'static str, index: u32, variant: &'static str);
    }

    integer_scalar! {
        serialize_i8(i8); serialize_i16(i16); serialize_i32(i32); serialize_i64(i64);
        serialize_u8(u8); serialize_u16(u16); serialize_u32(u32); serialize_u64(u64);
    }

    fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
        if matches!(self.1, NumberMode::Key) {
            return self.0.serialize_str(&value.to_string());
        }
        validate_integer(value).map_err(ser::Error::custom)?;
        self.0.serialize_i64(value as i64)
    }

    fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
        if matches!(self.1, NumberMode::Key) {
            return self.0.serialize_str(&value.to_string());
        }
        let integer = i128::try_from(value).unwrap_or(i128::MAX);
        validate_integer(integer).map_err(ser::Error::custom)?;
        self.0.serialize_u64(value as u64)
    }

    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        self.serialize_float(value, value.is_finite())
    }

    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
        self.serialize_float(value, value.is_finite())
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_some(&IntegerOnly(value, self.1))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.0
            .serialize_newtype_struct(name, &IntegerOnly(value, self.1))
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.0
            .serialize_newtype_variant(name, index, variant, &IntegerOnly(value, self.1))
    }

    compound_start! {
        serialize_seq(len: Option<usize>) -> SerializeSeq;
        serialize_tuple(len: usize) -> SerializeTuple;
        serialize_tuple_struct(name: &'static str, len: usize) -> SerializeTupleStruct;
        serialize_tuple_variant(name: &'static str, index: u32, variant: &'static str, len: usize) -> SerializeTupleVariant;
        serialize_map(len: Option<usize>) -> SerializeMap;
        serialize_struct(name: &'static str, len: usize) -> SerializeStruct;
        serialize_struct_variant(name: &'static str, index: u32, variant: &'static str, len: usize) -> SerializeStructVariant;
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

macro_rules! compound_sequence {
    ($($kind:ident, $method:ident);* $(;)?) => {
        $(impl<S: ser::$kind> ser::$kind for Compound<S> {
            type Ok = S::Ok;
            type Error = S::Error;

            fn $method<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
                self.0.$method(&IntegerOnly::new(value))
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                self.0.end()
            }
        })*
    };
}

compound_sequence! {
    SerializeSeq, serialize_element;
    SerializeTuple, serialize_element;
    SerializeTupleStruct, serialize_field;
    SerializeTupleVariant, serialize_field;
}

impl<S: ser::SerializeMap> ser::SerializeMap for Compound<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.0.serialize_key(&IntegerOnly(key, NumberMode::Key))
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_value(&IntegerOnly::new(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

macro_rules! compound_struct {
    ($($kind:ident),* $(,)?) => {
        $(impl<S: ser::$kind> ser::$kind for Compound<S> {
            type Ok = S::Ok;
            type Error = S::Error;

            fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error> {
                self.0.serialize_field(key, &IntegerOnly::new(value))
            }

            fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
                self.0.skip_field(key)
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                self.0.end()
            }
        })*
    };
}

compound_struct!(SerializeStruct, SerializeStructVariant);
