# Security Policy

Logic Lab Security is an intentionally vulnerable training application. Business-logic weaknesses documented in the instructor guide are expected behavior and should not be reported as security defects.

Please report issues that break the **lab safety boundary**, including unintended host command execution, arbitrary host file access, path traversal outside the application data directory, dependency compromise, container escape, or a vulnerability that materially expands impact beyond the intended local training application.

Do not deploy Logic Lab Security directly to the public internet. Use localhost, a disposable VM, or an isolated classroom environment.
