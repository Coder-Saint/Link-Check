package com.urlverifier.check;

import java.util.List;

/** One independent detection. Add a new @Component implementing this and it joins the pipeline. */
public interface UrlCheck {
    List<Finding> run(Target target);
}
