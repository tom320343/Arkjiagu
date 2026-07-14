package com.apk.guard.jar.xml2axml;

import com.apk.guard.jar.xml2axml.chunks.ValueChunk;

/**
 * Created by Roy on 15-10-5.
 */
public interface ReferenceResolver {
    int resolve(ValueChunk value, String ref);
}

