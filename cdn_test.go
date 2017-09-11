package ali_cdn_refresh

import "testing"

func Test_RefrechUrl(t *testing.T) {
	accessKeyId, accessKeySecret:="",""
	err:=RefrechUrl(accessKeyId, accessKeySecret,"cdn.vrcdkj.cn/Act-Snapshot/7867e4ffbb454a5f98f5fabee99de4e7/1504749066455tw8s84n09tz9jejjtw0b8d7vi.mp4")
t.Log(err)
}

