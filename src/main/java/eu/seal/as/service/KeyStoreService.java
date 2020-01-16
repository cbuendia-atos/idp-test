/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.service;

import io.jsonwebtoken.SignatureAlgorithm;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

/**
 *
 * @author nikos
 */
public interface KeyStoreService {

//    public Key getJWTSigningKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException;
    public Key getSigningKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException,UnsupportedEncodingException;
    public Key getJWTPublicKey() throws KeyStoreException, UnsupportedEncodingException;
    public Key getHttpSigPublicKey() throws KeyStoreException, UnsupportedEncodingException;
    public SignatureAlgorithm getAlgorithm();
    public String getFingerPrint() throws KeyStoreException, UnsupportedEncodingException;;
}