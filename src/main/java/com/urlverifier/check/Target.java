package com.urlverifier.check;

import com.urlverifier.net.SafeHttpClient.Trace;

public record Target(ParsedUrl url, Trace trace) {}
