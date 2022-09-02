# Docker Example

If you would like to see how shellclear works as a command line and shell plugin, you can run this docker image by running the following command

```sh
docker build -t shellclear .
docker run -it shellclear bash
```

After exec to the container you can:
1. See shellclear findings when open the shell
2. [See sensitive data](../../README.md#eyes-find-sensitive-commands)
3. [Delete sensitive data](../../README.md#broom-clear-findings-)
4. See more features in [README file](../../README.md)