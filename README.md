# goan

Golang implementation [ANProto](https://github.com/evbogue/ANProto): the Authenticated and Non-networked protocol or ANother protocol

## Testing

Integration tests verify that messages can be opened back and forth from the javascript implementation and golang.

- Copy [`an.js`](https://github.com/evbogue/ANProto/blob/main/an.js) to `./an.js`

Run: 

```
go test ./... -v
```
