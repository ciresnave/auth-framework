//! Common test helpers and macros for better error handling

/// Macro to replace unwrap() with expect() that provides context
#[allow(unused_macros)]
macro_rules! expect_ok {
    ($result:expr, $msg:expr) => {
        $result.expect($msg)
    };
    ($result:expr) => {
        $result.expect("Operation should succeed in test context")
    };
}

/// Macro to replace unwrap() on Option with expect() that provides context
#[allow(unused_macros)]
macro_rules! expect_some {
    ($option:expr, $msg:expr) => {
        $option.expect($msg)
    };
    ($option:expr) => {
        $option.expect("Option should contain a value in test context")
    };
}

/// Macro for asserting async operations succeed with better error messages
#[allow(unused_macros)]
macro_rules! assert_async_ok {
    ($async_result:expr, $msg:expr) => {
        assert!($async_result.await.is_ok(), $msg);
    };
    ($async_result:expr) => {
        assert!(
            $async_result.await.is_ok(),
            "Async operation should succeed"
        );
    };
}

/// Macro for asserting async operations fail with better error messages
#[allow(unused_macros)]
macro_rules! assert_async_err {
    ($async_result:expr, $msg:expr) => {
        assert!($async_result.await.is_err(), $msg);
    };
    ($async_result:expr) => {
        assert!($async_result.await.is_err(), "Async operation should fail");
    };
}

#[allow(unused_imports)]
pub(crate) use {assert_async_err, assert_async_ok, expect_ok, expect_some};
