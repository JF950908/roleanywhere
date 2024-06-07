# roleanywhere
role any where linux script
# go mod 创建项目
go mod init <module-name>
# 进入项目创建package
mkdir main
# 创建文件
vi roleanywhere.go
# 下载扩展
go get github.com/aws/aws-sdk-go-v2/aws
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/credentials
go get github.com/aws/aws-sdk-go-v2/service/s3

# 编译成执行文件
go build  roleanywhere.go

