use crate::secret::{SecretKey,ExpandedSecretKey};
use crate::public::PublicKey;
use crate::signature::Signature;
use crate::Keypair;

use pyo3::prelude::*;
use pyo3::types::{PyBytes,PyTuple};
use pyo3::exceptions::ValueError;
use pyo3::wrap_pyfunction;
use rand::thread_rng;
use std::string::ToString;
use std::boxed::Box;

#[pyfunction]
fn decrypt(_py: Python<'_>, secret: &PyBytes, public: &PyBytes, enc_msg: &PyBytes)
    -> PyResult<PyObject> {
    let secret = match SecretKey::from_bytes(secret.as_bytes()) {
        Ok(secret) => secret,
        Err(err) => return Err(ValueError::py_err(err.to_string()))
    };
    let expand = ExpandedSecretKey::from(&secret);
    let public = match PublicKey::from_bytes(public.as_bytes()) {
        Ok(public) => public,
        Err(err) => return Err(ValueError::py_err(err.to_string()))
    };
    let ecdhe = expand.shared_key(&public);
    match ecdhe.decrypt(enc_msg.as_bytes()) {
        Ok(message) => Ok(PyObject::from(PyBytes::new(_py, message.as_slice()))),
        Err(err) => Err(ValueError::py_err(err.to_string()))
    }
}

#[pyfunction]
fn encrypt(_py: Python<'_>, secret: &PyBytes, public: &PyBytes, message: &PyBytes)
    -> PyResult<PyObject> {
    let secret = match SecretKey::from_bytes(secret.as_bytes()) {
        Ok(secret) => secret,
        Err(err) => return Err(ValueError::py_err(err.to_string()))
    };
    let expand = ExpandedSecretKey::from(&secret);
    let public = match PublicKey::from_bytes(public.as_bytes()) {
        Ok(public) => public,
        Err(err) => return Err(ValueError::py_err(err.to_string()))
    };
    let mut ecdhe = expand.shared_key(&public);
    let enc_msg = ecdhe.encrypt(message.as_bytes());
    Ok(PyObject::from(PyBytes::new(_py, enc_msg.as_slice())))
}

#[pyfunction]
fn verify(message: &PyBytes, signature: &PyBytes, public: &PyBytes) -> PyResult<()> {
    let public = match PublicKey::from_bytes(public.as_bytes()) {
        Ok(public) => public,
        Err(err) => return Err(ValueError::py_err(err.to_string()))
    };
    let signature = match Signature::from_bytes(signature.as_bytes()) {
        Ok(signature) => signature,
        Err(err) => return Err(ValueError::py_err(err.to_string()))
    };
    match public.verify(message.as_bytes(), &signature) {
        Ok(()) => Ok(()),
        Err(err) => Err(ValueError::py_err(err.to_string()))
    }
}

#[pyfunction]
fn sign(_py: Python<'_>, message: &PyBytes, secret: &PyBytes) -> PyResult<PyObject> {
    let secret = match SecretKey::from_bytes(secret.as_bytes()){
        Ok(secret) => secret,
        Err(err) => return Err(ValueError::py_err(err.to_string()))
    };
    let public = PublicKey::from(&secret);
    let pair = Keypair{secret, public};
    let sig = pair.sign(message.as_bytes());
    Ok(PyObject::from(PyBytes::new(_py, &sig.to_bytes())))
}

#[pyfunction]
fn secret2public(_py: Python<'_>, secret: &PyBytes) -> PyResult<PyObject> {
    let secret = match SecretKey::from_bytes(secret.as_bytes()){
        Ok(secret) => secret,
        Err(err) => return Err(ValueError::py_err(err.to_string()))
    };
    let public = PublicKey::from(&secret);
    Ok(PyObject::from(PyBytes::new(_py, public.as_bytes())))
}

#[pyfunction]
fn generate_keypair(_py: Python<'_>) -> Py<PyTuple> {
    let mut cspring = thread_rng();
    let pair = Keypair::generate(&mut cspring);
    PyTuple::new(_py, &[
        PyBytes::new(_py, pair.secret.as_bytes()),
        PyBytes::new(_py, pair.public.as_bytes())
    ])
}

/// This module is a python module implemented in Rust.
#[pymodule]
fn nem_ed25519_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(decrypt))?;
    m.add_wrapped(wrap_pyfunction!(encrypt))?;
    m.add_wrapped(wrap_pyfunction!(sign))?;
    m.add_wrapped(wrap_pyfunction!(verify))?;
    m.add_wrapped(wrap_pyfunction!(secret2public))?;
    m.add_wrapped(wrap_pyfunction!(generate_keypair))?;
    Ok(())
}
