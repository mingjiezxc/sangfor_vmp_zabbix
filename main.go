package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var (
	loginUrl      = "https://10.0.251.40/vapi/extjs/access/ticket"
	vmsUrl        = "https://10.0.251.40/vapi/extjs/cluster/vms"
	hostUrl       = "https://10.0.251.40/vapi/extjs/index/host_list"
	storageUrl    = "https://10.0.251.40/vapi/json/vs/vs_status/vs_get_volume_list_realtime"
	disksUrl      = "https://10.0.251.40/vapi/json/vs/vs_config/get_all_disks"
	vmpUser       = "zabbix"
	vmpPassword   = ""
	loginUsername = ""
	loginTicket   = ""
	zabbixHost    = "10.0.28.230"
	zabbixPort    = 10051
)

func main() {
	err := Login()
	if err != nil {
		fmt.Println(err.Error())
	}

	err = SenderHosts()
	if err != nil {
		fmt.Println(err.Error())
	}

	err = SenderVms()
	if err != nil {
		fmt.Println(err.Error())
	}

	err = SenderStorages()
	if err != nil {
		fmt.Println(err.Error())
	}

	err = SenderDisks()
	if err != nil {
		fmt.Println(err.Error())
	}

}

func SenderDisks() (err error) {
	body, err := HttpGet(disksUrl)

	var diskInfo DisksInfo
	err = json.Unmarshal(body, &diskInfo)

	var metrics []*Metric

	// add vm dir
	var DiskList []DiskDir
	for i := 0; i < len(diskInfo.Data.Disks); i++ {
		DiskList = append(DiskList, DiskDir{
			DiskID:    diskInfo.Data.Disks[i].Disk,
			DiskAlias: diskInfo.Data.Disks[i].IP + "_" + diskInfo.Data.Disks[i].DiskAlias,
		})
	}

	DiskDirJson, _ := json.Marshal(DiskList)
	metrics = append(metrics, NewMetric("VMP", "vmp.disks", fmt.Sprintf("%s", DiskDirJson)))

	// add storage info

	for i := 0; i < len(diskInfo.Data.Disks); i++ {
		hostName := diskInfo.Data.Disks[i].Disk
		metrics = AutoValFields(metrics, hostName, diskInfo.Data.Disks[i])
		metrics = AutoValFields(metrics, hostName, diskInfo.Data.Disks[i].Iostat)
	}

	// Create instance of Packet class
	packet := NewPacket(metrics)

	// Send packet to zabbix
	z := NewSender(zabbixHost, zabbixPort)
	z.Send(packet)

	return

}

func SenderStorages() (err error) {
	body, err := HttpGet(storageUrl)

	var storageInfo StoragesInfo
	err = json.Unmarshal(body, &storageInfo)

	var metrics []*Metric

	// add vm dir
	var storageList []StorageDir
	for i := 0; i < len(storageInfo.Data.Volumes); i++ {
		storageList = append(storageList, StorageDir{storageInfo.Data.Volumes[i].ID})
	}

	storageDirJson, _ := json.Marshal(storageList)
	metrics = append(metrics, NewMetric("VMP", "vmp.storages", fmt.Sprintf("%s", storageDirJson)))

	// add storage info
	for i := 0; i < len(storageInfo.Data.Volumes); i++ {
		metrics = append(metrics, NewMetric(storageInfo.Data.Volumes[i].ID, "name", storageInfo.Data.Volumes[i].Name))
		metrics = append(metrics, NewMetric(storageInfo.Data.Volumes[i].ID, "write_ratio", strconv.FormatInt(storageInfo.Data.Volumes[i].WriteRatio, 10)))
		metrics = append(metrics, NewMetric(storageInfo.Data.Volumes[i].ID, "read_ratio", strconv.FormatInt(storageInfo.Data.Volumes[i].ReadRatio, 10)))
		metrics = append(metrics, NewMetric(storageInfo.Data.Volumes[i].ID, "type", storageInfo.Data.Volumes[i].Type))

		metrics = append(metrics, NewMetric(storageInfo.Data.Volumes[i].ID, "vms_running", strconv.Itoa(storageInfo.Data.Volumes[i].VmsRunning)))
		metrics = append(metrics, NewMetric(storageInfo.Data.Volumes[i].ID, "vms_total", strconv.Itoa(storageInfo.Data.Volumes[i].VmsTotal)))

		metrics = append(metrics, NewMetric(storageInfo.Data.Volumes[i].ID, "total", strconv.FormatInt(storageInfo.Data.Volumes[i].Total, 10)))
		metrics = append(metrics, NewMetric(storageInfo.Data.Volumes[i].ID, "used", strconv.FormatInt(storageInfo.Data.Volumes[i].Used, 10)))
		metrics = append(metrics, NewMetric(storageInfo.Data.Volumes[i].ID, "avail", strconv.FormatInt(storageInfo.Data.Volumes[i].Avail, 10)))
	}

	// Create instance of Packet class
	packet := NewPacket(metrics)

	// Send packet to zabbix
	z := NewSender(zabbixHost, zabbixPort)
	z.Send(packet)

	return

}

func SenderHosts() (err error) {
	body, err := HttpGet(hostUrl)

	var hostsInfo HostsInfo
	err = json.Unmarshal(body, &hostsInfo)

	var metrics []*Metric

	// add vm dir
	var hostList []HostDir
	for i := 0; i < len(hostsInfo.Data); i++ {
		hostList = append(hostList, HostDir{hostsInfo.Data[i].Name})
	}

	vmDirJson, _ := json.Marshal(hostList)
	metrics = append(metrics, NewMetric("VMP", "vmp.hosts", fmt.Sprintf("%s", vmDirJson)))

	// add vm info
	for i := 0; i < len(hostsInfo.Data); i++ {
		metrics = append(metrics, NewMetric(hostsInfo.Data[i].Name, "name", JsonRatioStr(hostsInfo.Data[i].Name)))
		metrics = append(metrics, NewMetric(hostsInfo.Data[i].Name, "alert", hostsInfo.Data[i].Alert))
		metrics = append(metrics, NewMetric(hostsInfo.Data[i].Name, "status", strconv.Itoa(hostsInfo.Data[i].Status)))
		metrics = append(metrics, NewMetric(hostsInfo.Data[i].Name, "id", hostsInfo.Data[i].ID))
		metrics = append(metrics, NewMetric(hostsInfo.Data[i].Name, "ip", hostsInfo.Data[i].IP))

		metrics = append(metrics, NewMetric(hostsInfo.Data[i].Name, "cpu_ratio", JsonRatioStr(hostsInfo.Data[i].CPURatio)))
		metrics = append(metrics, NewMetric(hostsInfo.Data[i].Name, "io_ratio", JsonRatioStr(hostsInfo.Data[i].IoRatio)))
		metrics = append(metrics, NewMetric(hostsInfo.Data[i].Name, "mem_ratio", JsonRatioStr(hostsInfo.Data[i].MemRatio)))
		metrics = append(metrics, NewMetric(hostsInfo.Data[i].Name, "remain_mem_ratio", JsonRatioStr(hostsInfo.Data[i].RemainMemRatio)))
	}

	// Create instance of Packet class
	packet := NewPacket(metrics)

	// Send packet to zabbix
	z := NewSender(zabbixHost, zabbixPort)
	z.Send(packet)

	return

}

func SenderVms() (err error) {
	body, err := HttpGet(vmsUrl)

	var vmsInfo VmsInfo
	err = json.Unmarshal(body, &vmsInfo)

	var metrics []*Metric

	// add vm dir
	var vmList []VmDir
	for i := 0; i < len(vmsInfo.Data); i++ {
		vmList = append(vmList, VmDir{vmsInfo.Data[i].Name, vmsInfo.Data[i].Vmid})
	}

	vmDirJson, _ := json.Marshal(vmList)
	metrics = append(metrics, NewMetric("VMP", "vmp.vms", fmt.Sprintf("%s", vmDirJson)))

	var iops_write_count int64
	var iops_read_count int64
	var disk_info_speed_read_count int64
	var disk_info_speed_write_count int64
	var flow_info_send_count int64
	var flow_info_receive_count int64
	var flow_info_send_package_count int64
	var flow_info_receive_package_count int64

	// add vm info
	for i := 0; i < len(vmsInfo.Data); i++ {
		zabbixHostName := strconv.FormatInt(vmsInfo.Data[i].Vmid, 10)

		iops_write_count = iops_write_count + vmsInfo.Data[i].DiskInfoIopsWrite
		iops_read_count = iops_read_count + vmsInfo.Data[i].DiskInfoIopsRead
		disk_info_speed_read_count = disk_info_speed_read_count + vmsInfo.Data[i].DiskInfoSpeedRead
		disk_info_speed_write_count = disk_info_speed_write_count + vmsInfo.Data[i].DiskInfoSpeedWrite
		flow_info_send_count = flow_info_send_count + vmsInfo.Data[i].FlowInfoSend
		flow_info_receive_count = flow_info_receive_count + vmsInfo.Data[i].FlowInfoReceive
		flow_info_send_package_count = flow_info_send_package_count + vmsInfo.Data[i].FlowInfoSendPackage
		flow_info_receive_package_count = flow_info_receive_package_count + vmsInfo.Data[i].FlowInfoReceivePackage

		metrics = append(metrics, NewMetric(zabbixHostName, "name", vmsInfo.Data[i].Name))
		metrics = append(metrics, NewMetric(zabbixHostName, "vmid", strconv.FormatInt(vmsInfo.Data[i].Vmid, 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "status", vmsInfo.Data[i].Status))
		metrics = append(metrics, NewMetric(zabbixHostName, "hstatus", strconv.Itoa(vmsInfo.Data[i].Hstatus)))
		metrics = append(metrics, NewMetric(zabbixHostName, "alert", vmsInfo.Data[i].Alert))

		metrics = append(metrics, NewMetric(zabbixHostName, "cores_number", vmsInfo.Data[i].CoresNumber))
		metrics = append(metrics, NewMetric(zabbixHostName, "memory", vmsInfo.Data[i].Memory))

		metrics = append(metrics, NewMetric(zabbixHostName, "cpu_ratio", JsonRatioStr(vmsInfo.Data[i].CPURatio)))
		metrics = append(metrics, NewMetric(zabbixHostName, "mem_ratio", JsonRatioStr(vmsInfo.Data[i].MemRatio)))
		metrics = append(metrics, NewMetric(zabbixHostName, "io_ratio", JsonRatioStr(vmsInfo.Data[i].IoRatio)))

		metrics = append(metrics, NewMetric(zabbixHostName, "res_mem_uesed", JsonRatioStr(vmsInfo.Data[i].ResMemUesed)))
		metrics = append(metrics, NewMetric(zabbixHostName, "res_disk_uesed", strconv.FormatInt(vmsInfo.Data[i].ResDiskUesed, 10)))

		metrics = append(metrics, NewMetric(zabbixHostName, "mem_status_ratio", JsonRatioStr(vmsInfo.Data[i].MemStatus.Ratio)))
		metrics = append(metrics, NewMetric(zabbixHostName, "mem_status_free", strconv.FormatInt(int64(vmsInfo.Data[i].MemStatus.Free), 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "mem_status_total", strconv.FormatInt(vmsInfo.Data[i].MemStatus.Total, 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "disk_status_ratio", JsonRatioStr(vmsInfo.Data[i].DiskStatus.Ratio)))
		metrics = append(metrics, NewMetric(zabbixHostName, "disk_status_free", strconv.FormatInt(vmsInfo.Data[i].DiskStatus.Free, 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "disk_status_total", strconv.FormatInt(vmsInfo.Data[i].DiskStatus.Total, 10)))

		metrics = append(metrics, NewMetric(zabbixHostName, "disk_info_iops_write", strconv.FormatInt(vmsInfo.Data[i].DiskInfoIopsWrite, 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "disk_info_iops_read", strconv.FormatInt(vmsInfo.Data[i].DiskInfoIopsRead, 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "disk_info_speed_write", strconv.FormatInt(vmsInfo.Data[i].DiskInfoSpeedWrite, 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "disk_info_speed_read", strconv.FormatInt(vmsInfo.Data[i].DiskInfoSpeedRead, 10)))

		metrics = append(metrics, NewMetric(zabbixHostName, "flow_info_send", strconv.FormatInt(vmsInfo.Data[i].FlowInfoSend, 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "flow_info_receive", strconv.FormatInt(vmsInfo.Data[i].FlowInfoReceive, 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "flow_info_send_package", strconv.FormatInt(vmsInfo.Data[i].FlowInfoSendPackage, 10)))
		metrics = append(metrics, NewMetric(zabbixHostName, "flow_info_receive_package", strconv.FormatInt(vmsInfo.Data[i].FlowInfoReceivePackage, 10)))

		metrics = append(metrics, NewMetric(zabbixHostName, "backup_info_backuptime", JsonRatioStr(vmsInfo.Data[i].BackupInfoBackuptime)))
		metrics = append(metrics, NewMetric(zabbixHostName, "backup_info_enable", strconv.Itoa(vmsInfo.Data[i].BackupInfoEnable)))

		metrics = append(metrics, NewMetric(zabbixHostName, "vmid", strconv.Itoa(int(vmsInfo.Data[i].Vmid))))
		metrics = append(metrics, NewMetric(zabbixHostName, "ip", vmsInfo.Data[i].IP))
	}

	metrics = append(metrics, NewMetric("VMP", "vmp.vms.disk.iops.read.count", fmt.Sprintf("%d", iops_read_count)))
	metrics = append(metrics, NewMetric("VMP", "vmp.vms.disk.iops.write.count", fmt.Sprintf("%d", iops_write_count)))

	metrics = append(metrics, NewMetric("VMP", "vmp.vms.disk.speed.read.count", fmt.Sprintf("%d", disk_info_speed_read_count)))
	metrics = append(metrics, NewMetric("VMP", "vmp.vms.disk.speed.write.count", fmt.Sprintf("%d", disk_info_speed_write_count)))
	metrics = append(metrics, NewMetric("VMP", "vmp.vms.flow.send.count", fmt.Sprintf("%d", flow_info_send_count)))
	metrics = append(metrics, NewMetric("VMP", "vmp.vms.flow.receive.count", fmt.Sprintf("%d", flow_info_receive_count)))
	metrics = append(metrics, NewMetric("VMP", "vmp.vms.flow.send.package.count", fmt.Sprintf("%d", flow_info_send_package_count)))
	metrics = append(metrics, NewMetric("VMP", "vmp.vms.flow.receive.package.count", fmt.Sprintf("%d", flow_info_receive_package_count)))

	// Create instance of Packet class
	packet := NewPacket(metrics)

	// Send packet to zabbix
	z := NewSender(zabbixHost, zabbixPort)
	z.Send(packet)

	return

}

func HttpGet(getUrl string) (body []byte, err error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", getUrl, nil)
	if err != nil {
		return
	}

	req.Header.Set("Cookie", fmt.Sprintf("username=%s; first_login=0; logoutTime=60; LoginAuthCookie=%s; lastOperTime=%d", loginUsername, loginTicket, time.Now().Unix()))
	resp, err := client.Do(req)
	if err != nil {
		return
	}

	body, err = ioutil.ReadAll(resp.Body)

	defer resp.Body.Close()

	return

}

func Login() (err error) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	body := strings.NewReader(fmt.Sprintf("username=%s&password=%s&privacy=1", vmpUser, vmpPassword))
	req, err := http.NewRequest("POST", loginUrl, body)
	if err != nil {
		// handle err
	}

	resp, err := client.Do(req)
	if err != nil {
		// handle err
	}
	defer resp.Body.Close()
	getBody, _ := ioutil.ReadAll(resp.Body)

	var loginVar LoginVar
	err = json.Unmarshal(getBody, &loginVar)
	if err != nil {
		return
	}

	loginUsername = loginVar.Data.Username
	loginTicket = loginVar.Data.Ticket
	return
}

type VmsInfo struct {
	Success int `json:"success"`
	Data    []struct {
		Hstatus           int    `json:"hstatus"`
		Hostname          string `json:"hostname"`
		Cfgstorage        string `json:"cfgstorage"`
		DiskInfoIopsWrite int64  `json:"disk_info_iops_write,omitempty"`
		DiskInfoIopsRead  int64  `json:"disk_info_iops_read,omitempty"`
		Ostype            string `json:"ostype"`
		IfIrsOn           int    `json:"if_irs_on"`
		Vmtype            string `json:"vmtype"`
		FlowInfoReceive   int64  `json:"flow_info_receive,omitempty"`
		Name              string `json:"name"`
		Urgent            int    `json:"urgent"`
		DiskStatus        struct {
			Ratio interface{} `json:"ratio"`
			Free  int64       `json:"free"`
			Total int64       `json:"total"`
		} `json:"disk_status,omitempty"`
		Memory              string        `json:"memory"`
		Graphics            int           `json:"graphics"`
		FlowInfoSendPackage int64         `json:"flow_info_send_package,omitempty"`
		DiskInfoSpeedWrite  int64         `json:"disk_info_speed_write,omitempty"`
		Status              string        `json:"status"`
		IP                  string        `json:"ip"`
		Ha                  int           `json:"ha"`
		DiskInfoSpeedRead   int64         `json:"disk_info_speed_read,omitempty"`
		Node                string        `json:"node"`
		Groupname           string        `json:"groupname"`
		Vmid                int64         `json:"vmid"`
		Vmpexp              int           `json:"vmpexp"`
		Alert               string        `json:"alert"`
		ResMemUesed         interface{}   `json:"res_mem_uesed"`
		CPURatio            interface{}   `json:"cpu_ratio"`
		AssociatedUser      string        `json:"associated_user"`
		ResDiskUesed        int64         `json:"res_disk_uesed"`
		Vmgroup             string        `json:"vmgroup"`
		Nets                []interface{} `json:"nets"`
		MemStatus           struct {
			Ratio interface{} `json:"ratio"`
			Free  int64       `json:"free"`
			Total int64       `json:"total"`
		} `json:"mem_status,omitempty"`
		IoRatio                interface{} `json:"io_ratio"`
		Host                   string      `json:"host"`
		Logo                   string      `json:"logo"`
		CoresNumber            string      `json:"cores_number"`
		FlowInfoSend           int64       `json:"flow_info_send,omitempty"`
		MemRatio               interface{} `json:"mem_ratio"`
		FlowInfoReceivePackage int64       `json:"flow_info_receive_package,omitempty"`

		TemplateUpdate string `json:"template_update,omitempty"`

		FullyClone   string      `json:"fully_clone,omitempty"`
		TemplateUUID string      `json:"template_uuid,omitempty"`
		Volatile     string      `json:"volatile,omitempty"`
		PlanTime     interface{} `json:"plan_time,omitempty"`

		BackupInfoBackuptime interface{} `json:"backup_info_backuptime,omitempty"`
		BackupInfoStorage    string      `json:"backup_info_storage,omitempty"`
		BackupInfoEnable     int         `json:"backup_info_enable,omitempty"`
		BackupInfoBackupsize string      `json:"backup_info_backupsize,omitempty"`
	} `json:"data"`
}

type LoginVar struct {
	Success int `json:"success"`
	Data    struct {
		Cap struct {
			Dc struct {
			} `json:"dc"`
			Access struct {
			} `json:"access"`
			Nodes struct {
			} `json:"nodes"`
			Vms struct {
			} `json:"vms"`
			Storage struct {
			} `json:"storage"`
		} `json:"cap"`
		ReadPrivs struct {
			Host                 int `json:"HOST"`
			VM                   int `json:"VM"`
			VMPower              int `json:"VM.Power"`
			VMCreate             int `json:"VM.Create"`
			VMExport             int `json:"VM.Export"`
			MANAGEIRS            int `json:"MANAGE.IRS"`
			VSOtherstorage       int `json:"VS.Otherstorage"`
			MANAGEClusterIP      int `json:"MANAGE.ClusterIP"`
			Vsw                  int `json:"VSW"`
			MANAGEDiskDefrag     int `json:"MANAGE.DiskDefrag"`
			VMConsole            int `json:"VM.Console"`
			MANAGEHA             int `json:"MANAGE.HA"`
			VMLogs               int `json:"VM.Logs"`
			VDISKDelete          int `json:"VDISK.Delete"`
			MANAGERecyclebin     int `json:"MANAGE.Recyclebin"`
			MANAGECheck          int `json:"MANAGE.Check"`
			VMClone              int `json:"VM.Clone"`
			VMSnapmanage         int `json:"VM.Snapmanage"`
			MANAGEUser           int `json:"MANAGE.User"`
			Vs                   int `json:"VS"`
			VDISKBackup          int `json:"VDISK.Backup"`
			Home                 int `json:"HOME"`
			VSVirtualstorage     int `json:"VS.Virtualstorage"`
			Manage               int `json:"MANAGE"`
			VDISKManage          int `json:"VDISK.Manage"`
			VMManage             int `json:"VM.Manage"`
			VMDelete             int `json:"VM.Delete"`
			VMMigrate            int `json:"VM.Migrate"`
			MANAGELogAlarm       int `json:"MANAGE.LogAlarm"`
			VMSuspend            int `json:"VM.Suspend"`
			MANAGEOnlineUpdate   int `json:"MANAGE.OnlineUpdate"`
			VSOverview           int `json:"VS.Overview"`
			MANAGEUpgrade        int `json:"MANAGE.Upgrade"`
			MANAGESYSConfig      int `json:"MANAGE.SYSConfig"`
			MANAGETime           int `json:"MANAGE.Time"`
			VMGroup              int `json:"VM.Group"`
			MANAGESYSDiagnosis   int `json:"MANAGE.SYSDiagnosis"`
			VMEdit               int `json:"VM.Edit"`
			HOSTPhysicalHost     int `json:"HOST.PhysicalHost"`
			MANAGEVMBackRecover  int `json:"MANAGE.VMBackRecover"`
			MANAGEAuthServ       int `json:"MANAGE.AuthServ"`
			MANAGESYSBackRecover int `json:"MANAGE.SYSBackRecover"`
			VMTemplate           int `json:"VM.Template"`
			MANAGEClusterMigrate int `json:"MANAGE.ClusterMigrate"`
			MANAGERole           int `json:"MANAGE.Role"`
			VDISKResize          int `json:"VDISK.Resize"`
			VMManagement         int `json:"VM.Management"`
		} `json:"read_privs"`
		Cluster      string `json:"cluster"`
		PasswordType string `json:"password_type"`
		DefaultIP    int    `json:"default_ip"`
		EditPrivs    struct {
			Host                 int `json:"HOST"`
			VM                   int `json:"VM"`
			VMPower              int `json:"VM.Power"`
			VMCreate             int `json:"VM.Create"`
			VMExport             int `json:"VM.Export"`
			MANAGEIRS            int `json:"MANAGE.IRS"`
			VSOtherstorage       int `json:"VS.Otherstorage"`
			MANAGEClusterIP      int `json:"MANAGE.ClusterIP"`
			Vsw                  int `json:"VSW"`
			MANAGEDiskDefrag     int `json:"MANAGE.DiskDefrag"`
			VMConsole            int `json:"VM.Console"`
			MANAGEHA             int `json:"MANAGE.HA"`
			VMLogs               int `json:"VM.Logs"`
			VDISKDelete          int `json:"VDISK.Delete"`
			MANAGERecyclebin     int `json:"MANAGE.Recyclebin"`
			MANAGECheck          int `json:"MANAGE.Check"`
			VMClone              int `json:"VM.Clone"`
			VMSnapmanage         int `json:"VM.Snapmanage"`
			MANAGEUser           int `json:"MANAGE.User"`
			Vs                   int `json:"VS"`
			VDISKBackup          int `json:"VDISK.Backup"`
			Home                 int `json:"HOME"`
			VSVirtualstorage     int `json:"VS.Virtualstorage"`
			Manage               int `json:"MANAGE"`
			VDISKManage          int `json:"VDISK.Manage"`
			VMManage             int `json:"VM.Manage"`
			VMDelete             int `json:"VM.Delete"`
			VMMigrate            int `json:"VM.Migrate"`
			MANAGELogAlarm       int `json:"MANAGE.LogAlarm"`
			VMSuspend            int `json:"VM.Suspend"`
			MANAGEOnlineUpdate   int `json:"MANAGE.OnlineUpdate"`
			VSOverview           int `json:"VS.Overview"`
			MANAGEUpgrade        int `json:"MANAGE.Upgrade"`
			MANAGESYSConfig      int `json:"MANAGE.SYSConfig"`
			MANAGETime           int `json:"MANAGE.Time"`
			VMGroup              int `json:"VM.Group"`
			MANAGESYSDiagnosis   int `json:"MANAGE.SYSDiagnosis"`
			VMEdit               int `json:"VM.Edit"`
			HOSTPhysicalHost     int `json:"HOST.PhysicalHost"`
			MANAGEVMBackRecover  int `json:"MANAGE.VMBackRecover"`
			MANAGEAuthServ       int `json:"MANAGE.AuthServ"`
			MANAGESYSBackRecover int `json:"MANAGE.SYSBackRecover"`
			VMTemplate           int `json:"VM.Template"`
			MANAGEClusterMigrate int `json:"MANAGE.ClusterMigrate"`
			MANAGERole           int `json:"MANAGE.Role"`
			VDISKResize          int `json:"VDISK.Resize"`
			VMManagement         int `json:"VM.Management"`
		} `json:"edit_privs"`
		LastOperTime        int    `json:"lastOperTime"`
		Username            string `json:"username"`
		ClientIP            string `json:"client_ip"`
		CSRFPreventionToken string `json:"CSRFPreventionToken"`
		FirstLogin          int    `json:"first_login"`
		Ticket              string `json:"ticket"`
		Roleid              string `json:"roleid"`
		LogoutTime          int    `json:"logoutTime"`
	} `json:"data"`
}

type HostsInfo struct {
	Success int `json:"success"`
	Data    []struct {
		Alert          string      `json:"alert"`
		CPURatio       interface{} `json:"cpu_ratio"`
		Master         int         `json:"master,omitempty"`
		IP             string      `json:"ip"`
		Status         int         `json:"status"`
		Name           string      `json:"name"`
		Novs           int         `json:"novs"`
		RemainMemRatio string      `json:"remain_mem_ratio"`
		Urgent         int         `json:"urgent"`
		IoRatio        interface{} `json:"io_ratio"`
		Graphics       int         `json:"graphics"`
		MemRatio       interface{} `json:"mem_ratio"`
		Type           string      `json:"type"`
		ID             string      `json:"id"`
		Protectmode    string      `json:"protectmode"`
	} `json:"data"`
	Total int `json:"total"`
}

type VmDir struct {
	VmName string `json:"{#VMNAME}"`
	Vmid   int64  `json:"{#VMID}"`
}

type HostDir struct {
	HostName string `json:"{#HOSTNAME}"`
}

type StorageDir struct {
	StorageID string `json:"{#STORAGEID}"`
}

type DiskDir struct {
	DiskID    string `json:"{#DISK}"`
	DiskAlias string `json:"{#DISKALIAS}"`
}

type StoragesInfo struct {
	Success int `json:"success"`
	Data    struct {
		Volumes []struct {
			WriteRatio int64  `json:"write_ratio"`
			Name       string `json:"name"`
			VmsRunning int    `json:"vms_running"`
			Total      int64  `json:"total"`
			ReadRatio  int64  `json:"read_ratio"`
			Avail      int64  `json:"avail"`
			Used       int64  `json:"used"`
			Nfstype    string `json:"nfstype"`
			ID         string `json:"id"`
			Type       string `json:"type"`
			VmsTotal   int    `json:"vms_total"`
		} `json:"volumes"`
		DataReady int `json:"data_ready"`
	} `json:"data"`
}

type DisksInfo struct {
	Success int `json:"success"`
	Data    struct {
		Volumes []struct {
			Hosts []struct {
				IP       string `json:"ip"`
				HostName string `json:"host_name"`
			} `json:"hosts"`
			VolumeID   string `json:"volume_id"`
			VolumeName string `json:"volume_name"`
		} `json:"volumes"`
		Disks []struct {
			Disk         string        `json:"disk"`
			VolumeName   string        `json:"volume_name"`
			DiskType     string        `json:"disk_type"`
			VolumeID     string        `json:"volume_id"`
			Status       string        `json:"status"`
			IP           string        `json:"ip"`
			DiskAlias    string        `json:"disk_alias"`
			IopsOk       int           `json:"iops_ok"`
			DiskLocation string        `json:"disk_location"`
			MajorFault   string        `json:"major_fault"`
			DiskSn       string        `json:"disk_sn"`
			DiskDump     int           `json:"disk_dump"`
			StorageType  string        `json:"storage_type"`
			ReadOk       string        `json:"read_ok"`
			Alert        []interface{} `json:"alert"`
			Dev          string        `json:"dev"`
			LifeOk       int           `json:"life_ok"`
			FaultList    []interface{} `json:"fault_list"`
			Iostat       struct {
				IoAwait         interface{} `json:"io_await"`
				IoWriteCount    int64       `json:"io_write_count"`
				IoReadCount     int64       `json:"io_read_count"`
				DiskPvsFreeSize interface{} `json:"disk_pvs_free_size"`
				IoReadRate      int64       `json:"io_read_rate"`
				DiskPvsSize     int64       `json:"disk_pvs_size"`
				IoWriteRate     int64       `json:"io_write_rate"`
			} `json:"iostat"`
			DiskName string `json:"disk_name"`
			HostName string `json:"host_name"`
			DiskSize int64  `json:"disk_size"`
			Fault    string `json:"fault"`
		} `json:"disks"`
		Total      int `json:"total"`
		DiskNumber struct {
			DiskNumTotal  int `json:"disk_num_total"`
			DiskNumData   int `json:"disk_num_data"`
			DiskNumBackup int `json:"disk_num_backup"`
			DiskNumNone   int `json:"disk_num_none"`
			DiskNumCache  int `json:"disk_num_cache"`
		} `json:"disk_number"`
	} `json:"data"`
}

func JsonRatioStr(i interface{}) (tmpStr string) {
	switch v := i.(type) {
	case string:
		tmpStr = v
	case float64:
		tmpStr = strconv.FormatFloat(v, 'E', -1, 64)
	case int64:
		tmpStr = strconv.FormatInt(v, 10)
	case int:
		tmpStr = strconv.Itoa(v)
	default:
		tmpStr = fmt.Sprintf("%v", v)
	}
	return
}

func AutoValFields(metrics []*Metric, hostName string, b interface{}) []*Metric {
	val := reflect.ValueOf(b)
	for i := 0; i < val.Type().NumField(); i++ {
		metrics = append(metrics, NewMetric(hostName, val.Type().Field(i).Tag.Get("json"), JsonRatioStr(val.Field(i))))
	}
	return metrics
}
