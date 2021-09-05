package id.co.swipepay.apigateway.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class StringUtils {
    public static <T> T stringToClass(String stringToConvert, Class<T> classType) {
        return new Gson().fromJson(stringToConvert, classType);
    }

    public static String classToString(Object obj) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(obj);
    }
}
