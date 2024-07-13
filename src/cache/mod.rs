use redis::{FromRedisValue, RedisResult, Value};


pub enum OptionalValue<T: FromRedisValue> {
    None,
    Some(T),
}

impl<T: FromRedisValue> FromRedisValue for OptionalValue<T> {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        match *v {
            Value::Nil => Ok(OptionalValue::None),
            _ => T::from_redis_value(v).map(|rv| OptionalValue::Some(rv)),
        }
    }
}

