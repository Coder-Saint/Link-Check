package com.urlverifier.scoring;

import com.urlverifier.check.Finding;
import com.urlverifier.net.SafeHttpClient.Hop;

import java.util.List;

public record AnalysisResult(String url, String finalUrl, int score, String verdict, String headline,
                             List<Finding> findings, List<Hop> hops, String fetchError, long millis) {}
