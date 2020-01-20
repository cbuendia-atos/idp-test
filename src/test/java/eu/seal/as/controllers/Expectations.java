package eu.seal.as.controllers;

import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.JsonBody;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import com.google.gson.Gson;

public class Expectations {

	private static Gson gson = new Gson();

	public static void createDefaultExpectations(ClientAndServer mockServer) {
		// GET
		getProduct(mockServer);

	}


	private static void getProduct(ClientAndServer mockServer) {
		String   products [] = new String[1];
		products[0]="blahba";
	
		mockServer.when(request().withMethod("GET")	)
				.respond(response().withStatusCode(200).withBody(gson.toJson(products)));

	}

}