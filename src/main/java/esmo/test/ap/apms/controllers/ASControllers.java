package esmo.test.ap.apms.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

import esmo.test.ap.apms.MemCacheConfig;
import esmo.test.ap.apms.model.enums.TypeEnum;
import esmo.test.ap.apms.model.factories.AttributeTypeFactory;
import esmo.test.ap.apms.model.pojo.AttributeSet;
import esmo.test.ap.apms.model.pojo.AttributeSetStatus;
import esmo.test.ap.apms.model.pojo.AttributeType;
import esmo.test.ap.apms.model.pojo.EntityMetadata;
import esmo.test.ap.apms.model.pojo.SessionMngrResponse;
import esmo.test.ap.apms.model.pojo.UpdateDataRequest;
import esmo.test.ap.apms.service.EsmoMetadataService;
import esmo.test.ap.apms.service.HttpSignatureService;
import esmo.test.ap.apms.service.KeyStoreService;
import esmo.test.ap.apms.service.NetworkService;
import esmo.test.ap.apms.service.ParameterService;
import esmo.test.ap.apms.service.impl.HttpSignatureServiceImpl;
import esmo.test.ap.apms.service.impl.NetworkServiceImpl;
import esmo.test.ap.apms.service.impl.SamlUtils;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Controllers managing IDP requests
 */

public class ASControllers {
	
    private final static Logger LOG = LoggerFactory.getLogger(ASControllers.class);

    @Autowired
    private CacheManager cacheManager; 
    
    private final NetworkService netServ;
    private final ParameterService paramServ;
    private final EsmoMetadataService metadataServ;
    private final KeyStoreService keyServ;
    
    public ASControllers(ParameterService paramServ, KeyStoreService keyServ,
            EsmoMetadataService metadataServ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, UnsupportedEncodingException, InvalidKeySpecException, IOException {
        this.paramServ = paramServ;
        this.metadataServ = metadataServ;
        this.keyServ = keyServ;
        Key signingKey = this.keyServ.getSigningKey();
        String fingerPrint = this.keyServ.getFingerPrint();
        HttpSignatureService httpSigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
        this.netServ = new NetworkServiceImpl(httpSigServ);
    }
    
    /*
     * Pass a standard authn request object to be handled by an auth source ms
     * @param msToken standard security token for microservice communication
     * @param model
     * @param redirectAttrs
     * @throws KeyStoreException
     */

    @RequestMapping(value = "/as/authenticate", method = {RequestMethod.POST, RequestMethod.GET})
    public String authenticate(@RequestParam(value = "msToken", required = true) String msToken, Model model, RedirectAttributes redirectAttrs) throws KeyStoreException {
        String sessionMngrUrl = paramServ.getParam("SESSION_MANAGER_URL");
        Cache memCache = this.cacheManager.getCache(MemCacheConfig.AP_SESSION);
        
        List<NameValuePair> requestParams = new ArrayList<NameValuePair>();
        requestParams.add(new NameValuePair("token", msToken));
        ObjectMapper mapper = new ObjectMapper();
        try {
        	SessionMngrResponse resp = mapper.readValue(netServ.sendGet(sessionMngrUrl, "/sm/validateToken", requestParams, 1), SessionMngrResponse.class);
            if (resp.getCode().toString().equals("OK") && StringUtils.isEmpty(resp.getError())) {
                String esmoSessionId = resp.getSessionData().getSessionId();
                String apMsSessionId = UUID.randomUUID().toString();
                LOG.info("SessionID " + esmoSessionId);
                requestParams.clear();
                requestParams.add(new NameValuePair("sessionId", esmoSessionId));
                
                //resp = mapper.readValue(netServ.sendGet(sessionMngrUrl, "/sm/getSessionData", requestParams, 1), SessionMngrResponse.class);
                Gson gson = new Gson();
                LinkedHashMap apRequest = (LinkedHashMap) resp.getSessionData().getSessionVariables().get("apRequest");
                String jsonApRequest = gson.toJson(apRequest, LinkedHashMap.class);
                
                LOG.info("Session: \n" + apRequest + "\n");
                LOG.info("Correct data + \n" + jsonApRequest);

                if (apRequest == null) {
                    LOG.error("no apRequest found in session " + esmoSessionId);
                    model.addAttribute("error", "No AP request attributes found in the Session! Please restart the process");
                    redirectAttrs.addFlashAttribute("errorMsg", "No AP request attributes found in the Session! Please restart the process");
                    return "redirect:/authfail";
                } else {

                    EntityMetadata apMsMetadata = metadataServ.getMetadata();

                    AttributeSet parsedApRequest = mapper.readValue(jsonApRequest, AttributeSet.class);
                    List<AttributeType> matchingRequestedAttributes = 
                    		Arrays.stream(parsedApRequest.getAttributes()).filter
                    		(attribute -> 
                    		{
                    			return Arrays.asList(apMsMetadata.getClaims()).contains(attribute.getFriendlyName());
                    		}).
                    		collect(Collectors.toList());

                    if (matchingRequestedAttributes.size() > 0) {
                        //memCache.put(apMsSessionId, mapper.writeValueAsString(resp)); //save the whole ESMO session in cache
                        return "redirect:/grap/saml/login?session=" + apMsSessionId;
                    }
                    LOG.error("Error, no supported attributes were found in the request");
                    Arrays.stream(parsedApRequest.getAttributes()).forEach(attr -> {
                        LOG.error(attr.getFriendlyName());
                    });
                    redirectAttrs.addFlashAttribute("errorMsg", "no supported attributes were found in the request");

                }
            } else {
                model.addAttribute("error", "Error validating token! " + resp.getError());
                LOG.error("something wring with the SM session!");
                LOG.error(resp.getError());
                LOG.error(resp.getCode().toString());
                redirectAttrs.addFlashAttribute("errorMsg", "Error validating token! " + resp.getError());
            }

        } catch (IOException ex) {
            LOG.info(ex.getMessage());
        } 
       catch (NoSuchAlgorithmException ex) {
            LOG.info(ex.getMessage());
        }
        return "redirect:/authfail";
    }
}
