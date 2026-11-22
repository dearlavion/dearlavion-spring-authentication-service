package com.dearlavion.authservice.hello;

import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Standalone: no Spring context, so no Mongo and none of the app's auth filters are involved. */
class HelloControllerTest {

    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new HelloController()).build();

    @Test
    void helloReturnsHelloWorldWithoutAnyHeaders() throws Exception {
        mvc.perform(get("/hello"))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello World"));
    }
}
