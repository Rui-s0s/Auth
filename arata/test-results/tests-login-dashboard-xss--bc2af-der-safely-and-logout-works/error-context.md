# Page snapshot

```yaml
- generic [ref=e1]:
  - heading "Login" [level=1] [ref=e2]
  - textbox "Username" [ref=e3]: <script>alert("Classic XSS")</script>
  - textbox "Password" [ref=e4]: ...
  - button "Login with Session" [active] [ref=e5]
  - button "Login with JWT" [ref=e6]
```