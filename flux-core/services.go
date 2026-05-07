package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func (a *App) validateNodesAvailableFromPayload(m map[string]any, tunnelType int) error {
	ids := map[int]bool{}
	add := func(id int) error {
		if id <= 0 {
			return errors.New("节点不能为空")
		}
		if ids[id] {
			return errors.New("节点重复")
		}
		ids[id] = true
		node, err := a.queryOne(`SELECT id,status FROM node WHERE id=?`, id)
		if err != nil {
			return errors.New("部分节点不存在")
		}
		if intVal(node["status"], 0) != 1 {
			return errors.New("部分节点不在线")
		}
		return nil
	}
	for _, item := range chainItems(m["inNodeId"]) {
		if err := add(intVal(item["nodeId"], 0)); err != nil {
			return err
		}
	}
	if tunnelType == 2 {
		for _, group := range chainGroups(m["chainNodes"]) {
			for _, item := range group {
				if err := add(intVal(item["nodeId"], 0)); err != nil {
					return err
				}
			}
		}
		outNodes := chainItems(m["outNodeId"])
		if len(outNodes) == 0 {
			return errors.New("出口不能为空")
		}
		for _, item := range outNodes {
			if err := add(intVal(item["nodeId"], 0)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) insertChainTunnels(tx *sql.Tx, tunnelID int64, m map[string]any) error {
	for _, item := range chainItems(m["inNodeId"]) {
		_, err := tx.Exec(`INSERT INTO chain_tunnel(tunnel_id,chain_type,node_id,port,strategy,inx,protocol) VALUES(?,?,?,?,?,?,?)`,
			tunnelID, 1, intVal(item["nodeId"], 0), nullableInt(item["port"]), strDefault(strVal(item["strategy"]), "fifo"), nullableInt(item["inx"]), strDefault(strVal(item["protocol"]), strDefault(strVal(m["protocol"]), "tls")))
		if err != nil {
			return err
		}
	}
	if intVal(m["type"], 1) != 2 {
		return nil
	}
	for groupIndex, group := range chainGroups(m["chainNodes"]) {
		for _, item := range group {
			nodeID := intVal(item["nodeId"], 0)
			port, err := a.getNodePort(nodeID, 0)
			if err != nil {
				return err
			}
			_, err = tx.Exec(`INSERT INTO chain_tunnel(tunnel_id,chain_type,node_id,port,strategy,inx,protocol) VALUES(?,?,?,?,?,?,?)`,
				tunnelID, 2, nodeID, port, strDefault(strVal(item["strategy"]), "fifo"), groupIndex+1, strDefault(strVal(item["protocol"]), "tls"))
			if err != nil {
				return err
			}
		}
	}
	for _, item := range chainItems(m["outNodeId"]) {
		nodeID := intVal(item["nodeId"], 0)
		port, err := a.getNodePort(nodeID, 0)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO chain_tunnel(tunnel_id,chain_type,node_id,port,strategy,inx,protocol) VALUES(?,?,?,?,?,?,?)`,
			tunnelID, 3, nodeID, port, strDefault(strVal(item["strategy"]), "fifo"), nullableInt(item["inx"]), strDefault(strVal(item["protocol"]), "tls"))
		if err != nil {
			return err
		}
	}
	return nil
}

func chainItems(v any) []map[string]any {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func chainGroups(v any) [][]map[string]any {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([][]map[string]any, 0, len(items))
	for _, group := range items {
		out = append(out, chainItems(group))
	}
	return out
}

func (a *App) refreshTunnelInIP(tunnelID int64) {
	rows, _ := a.queryMaps(`SELECT n.server_ip FROM chain_tunnel ct JOIN node n ON n.id=ct.node_id WHERE ct.tunnel_id=? AND ct.chain_type=1 ORDER BY ct.id ASC`, tunnelID)
	var ips []string
	for _, row := range rows {
		if ip := strVal(row["serverIp"]); ip != "" {
			ips = append(ips, ip)
		}
	}
	if len(ips) > 0 {
		_, _ = a.db.Exec(`UPDATE tunnel SET in_ip=? WHERE id=?`, strings.Join(ips, ","), tunnelID)
	}
}

func (a *App) getNodePort(nodeID int, excludeForwardID int) (int, error) {
	node, err := a.queryOne(`SELECT port FROM node WHERE id=?`, nodeID)
	if err != nil {
		return 0, errors.New("节点不存在")
	}
	used := map[int]bool{}
	chains, _ := a.queryMaps(`SELECT port FROM chain_tunnel WHERE node_id=? AND port IS NOT NULL`, nodeID)
	for _, c := range chains {
		used[intVal(c["port"], 0)] = true
	}
	forwards, _ := a.queryMaps(`SELECT port FROM forward_port WHERE node_id=? AND forward_id<>?`, nodeID, excludeForwardID)
	for _, f := range forwards {
		used[intVal(f["port"], 0)] = true
	}
	for _, p := range parsePorts(strVal(node["port"])) {
		if !used[p] {
			return p, nil
		}
	}
	return 0, errors.New("节点端口已满，无可用端口")
}

func (a *App) applyTunnelChain(tunnelID int64) error {
	tunnel, err := a.queryOne(`SELECT * FROM tunnel WHERE id=?`, tunnelID)
	if err != nil {
		return err
	}
	if intVal(tunnel["type"], 1) != 2 {
		return nil
	}
	all, _ := a.queryMaps(`SELECT * FROM chain_tunnel WHERE tunnel_id=? ORDER BY chain_type ASC,inx ASC,id ASC`, tunnelID)
	nodes, err := a.nodesForChain(all)
	if err != nil {
		return err
	}
	var inNodes, outNodes []map[string]any
	grouped := map[int][]map[string]any{}
	for _, c := range all {
		switch intVal(c["chainType"], 0) {
		case 1:
			inNodes = append(inNodes, c)
		case 2:
			grouped[intVal(c["inx"], 0)] = append(grouped[intVal(c["inx"], 0)], c)
		case 3:
			outNodes = append(outNodes, c)
		}
	}
	groups := orderedGroups(grouped)
	for _, in := range inNodes {
		target := outNodes
		if len(groups) > 0 {
			target = groups[0]
		}
		if len(target) > 0 {
			if err := a.addChainToNode(int64(intVal(in["nodeId"], 0)), tunnelID, target, nodes); err != nil {
				return err
			}
		}
	}
	for i, group := range groups {
		for _, item := range group {
			target := outNodes
			if i+1 < len(groups) {
				target = groups[i+1]
			}
			if len(target) > 0 {
				if err := a.addChainToNode(int64(intVal(item["nodeId"], 0)), tunnelID, target, nodes); err != nil {
					return err
				}
			}
			if err := a.addChainService(int64(intVal(item["nodeId"], 0)), item, nodes); err != nil {
				return err
			}
		}
	}
	for _, out := range outNodes {
		if err := a.addChainService(int64(intVal(out["nodeId"], 0)), out, nodes); err != nil {
			return err
		}
	}
	return nil
}

func orderedGroups(grouped map[int][]map[string]any) [][]map[string]any {
	var out [][]map[string]any
	for i := 1; ; i++ {
		group, ok := grouped[i]
		if !ok {
			break
		}
		out = append(out, group)
	}
	return out
}

func (a *App) nodesForChain(chains []map[string]any) (map[int]map[string]any, error) {
	nodes := map[int]map[string]any{}
	for _, c := range chains {
		id := intVal(c["nodeId"], 0)
		if _, ok := nodes[id]; ok {
			continue
		}
		node, err := a.queryOne(`SELECT * FROM node WHERE id=?`, id)
		if err != nil {
			return nil, errors.New("部分节点不存在")
		}
		nodes[id] = node
	}
	return nodes, nil
}

func (a *App) addChainToNode(nodeID int64, tunnelID int64, targets []map[string]any, nodes map[int]map[string]any) error {
	payloadNodes := make([]any, 0, len(targets))
	for i, target := range targets {
		targetNode := nodes[intVal(target["nodeId"], 0)]
		payloadNodes = append(payloadNodes, map[string]any{
			"name":      fmt.Sprintf("node_%d", i+1),
			"addr":      processServerAddress(strVal(targetNode["serverIp"]) + ":" + strconv.Itoa(intVal(target["port"], 0))),
			"connector": map[string]any{"type": "relay"},
			"dialer":    map[string]any{"type": strDefault(strVal(target["protocol"]), "tls")},
		})
	}
	local := nodes[int(nodeID)]
	hop := map[string]any{
		"name": "hop_" + strconv.FormatInt(tunnelID, 10),
		"selector": map[string]any{
			"strategy":    strDefault(strVal(targets[0]["strategy"]), "fifo"),
			"maxFails":    1,
			"failTimeout": "600s",
		},
		"nodes": payloadNodes,
	}
	if iface := strVal(local["interfaceName"]); iface != "" {
		hop["interface"] = iface
	}
	resp, err := a.sendAgentCommand(nodeID, "AddChains", map[string]any{
		"name": "chains_" + strconv.FormatInt(tunnelID, 10),
		"hops": []any{hop},
	})
	if err != nil {
		return err
	}
	if resp.Message != "OK" && !strings.Contains(resp.Message, "exists") {
		return errors.New(resp.Message)
	}
	return nil
}

func (a *App) addChainService(nodeID int64, chain map[string]any, nodes map[int]map[string]any) error {
	node := nodes[intVal(chain["nodeId"], 0)]
	service := map[string]any{
		"name":     strconv.Itoa(intVal(chain["tunnelId"], 0)) + "_tls",
		"addr":     strDefault(strVal(node["tcpListenAddr"]), "[::]") + ":" + strconv.Itoa(intVal(chain["port"], 0)),
		"handler":  map[string]any{"type": "relay"},
		"listener": map[string]any{"type": strDefault(strVal(chain["protocol"]), "tls")},
	}
	if intVal(chain["chainType"], 0) == 2 {
		service["handler"].(map[string]any)["chain"] = "chains_" + strconv.Itoa(intVal(chain["tunnelId"], 0))
	}
	if intVal(chain["chainType"], 0) == 3 {
		if iface := strVal(node["interfaceName"]); iface != "" {
			service["metadata"] = map[string]any{"interface": iface}
		}
	}
	resp, err := a.sendAgentCommand(nodeID, "AddService", []any{service})
	if err != nil {
		return err
	}
	if resp.Message != "OK" && !strings.Contains(resp.Message, "exists") {
		return errors.New(resp.Message)
	}
	return nil
}

func (a *App) deleteTunnelByID(id int) error {
	if id == 0 {
		return errors.New("隧道不存在")
	}
	forwards, _ := a.queryMaps(`SELECT id FROM forward WHERE tunnel_id=?`, id)
	for _, f := range forwards {
		_ = a.deleteForwardByID(intVal(f["id"], 0), true)
	}
	chains, _ := a.queryMaps(`SELECT * FROM chain_tunnel WHERE tunnel_id=?`, id)
	for _, c := range chains {
		nodeID := int64(intVal(c["nodeId"], 0))
		switch intVal(c["chainType"], 0) {
		case 1:
			_, _ = a.sendAgentCommand(nodeID, "DeleteChains", map[string]any{"chain": "chains_" + strconv.Itoa(id)})
		case 2:
			_, _ = a.sendAgentCommand(nodeID, "DeleteChains", map[string]any{"chain": "chains_" + strconv.Itoa(id)})
			_, _ = a.sendAgentCommand(nodeID, "DeleteService", map[string]any{"services": []string{strconv.Itoa(id) + "_tls"}})
		case 3:
			_, _ = a.sendAgentCommand(nodeID, "DeleteService", map[string]any{"services": []string{strconv.Itoa(id) + "_tls"}})
		}
	}
	_, _ = a.db.Exec(`DELETE FROM forward_port WHERE forward_id IN (SELECT id FROM forward WHERE tunnel_id=?)`, id)
	_, _ = a.db.Exec(`DELETE FROM forward WHERE tunnel_id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM user_tunnel WHERE tunnel_id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM chain_tunnel WHERE tunnel_id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM tunnel WHERE id=?`, id)
	return nil
}

func (a *App) checkForwardPermission(u CurrentUser, tunnelID int, excludeForwardID int) error {
	tunnel, err := a.queryOne(`SELECT * FROM tunnel WHERE id=?`, tunnelID)
	if err != nil || intVal(tunnel["status"], 0) != 1 {
		return errors.New("隧道不存在或已禁用")
	}
	if err := a.checkTunnelNodesActive(tunnelID); err != nil {
		return err
	}
	if u.RoleID == 0 {
		return nil
	}
	user, err := a.queryOne(`SELECT * FROM user WHERE id=?`, u.ID)
	if err != nil || intVal(user["status"], 0) != 1 {
		return errors.New("用户已到期或被禁用")
	}
	if exp := intVal(user["expTime"], 0); exp > 0 && exp <= int(nowMS()) {
		return errors.New("当前账号已到期")
	}
	if intVal(user["flow"], 0) > 0 && intVal(user["flow"], 0) != 99999 {
		limit := int64(intVal(user["flow"], 0)) * bytesToGB
		if int64(intVal(user["inFlow"], 0)+intVal(user["outFlow"], 0)) >= limit {
			return errors.New("用户总流量已用完")
		}
	}
	ut, err := a.queryOne(`SELECT * FROM user_tunnel WHERE user_id=? AND tunnel_id=?`, u.ID, tunnelID)
	if err != nil {
		return errors.New("你没有该隧道权限")
	}
	if intVal(ut["status"], 0) != 1 {
		return errors.New("隧道权限已禁用")
	}
	if exp := intVal(ut["expTime"], 0); exp > 0 && exp <= int(nowMS()) {
		return errors.New("该隧道权限已到期")
	}
	if intVal(ut["flow"], 0) > 0 && intVal(ut["flow"], 0) != 99999 {
		limit := int64(intVal(ut["flow"], 0)) * bytesToGB
		if int64(intVal(ut["inFlow"], 0)+intVal(ut["outFlow"], 0)) >= limit {
			return errors.New("该隧道流量已用完")
		}
	}
	userForwardCount := a.count(`SELECT COUNT(*) FROM forward WHERE user_id=? AND id<>?`, u.ID, excludeForwardID)
	if intVal(user["num"], 0) > 0 && intVal(user["num"], 0) != 99999 && userForwardCount >= intVal(user["num"], 0) {
		return errors.New("用户总转发数量已达上限")
	}
	tunnelForwardCount := a.count(`SELECT COUNT(*) FROM forward WHERE user_id=? AND tunnel_id=? AND id<>?`, u.ID, tunnelID, excludeForwardID)
	if intVal(ut["num"], 0) > 0 && intVal(ut["num"], 0) != 99999 && tunnelForwardCount >= intVal(ut["num"], 0) {
		return errors.New("该隧道转发数量已达上限")
	}
	return nil
}

func (a *App) checkTunnelNodesActive(tunnelID int) error {
	return nil
}

func (a *App) allocateForwardPorts(tx *sql.Tx, tunnelID int, requestedPort int, forwardID int64) (map[int]int, error) {
	entries, _ := a.queryMaps(`SELECT * FROM chain_tunnel WHERE tunnel_id=? AND chain_type=1`, tunnelID)
	if len(entries) == 0 {
		return nil, errors.New("隧道入口节点为空")
	}
	available := map[int][]int{}
	for _, entry := range entries {
		nodeID := intVal(entry["nodeId"], 0)
		ports, err := a.availablePorts(nodeID, int(forwardID))
		if err != nil {
			return nil, err
		}
		available[nodeID] = ports
	}
	result := map[int]int{}
	if requestedPort > 0 {
		for nodeID, ports := range available {
			if !containsInt(ports, requestedPort) {
				return nil, fmt.Errorf("指定端口 %d 不可用", requestedPort)
			}
			result[nodeID] = requestedPort
		}
		return result, nil
	}
	common := map[int]bool{}
	for _, p := range available[intVal(entries[0]["nodeId"], 0)] {
		common[p] = true
	}
	for _, ports := range available {
		next := map[int]bool{}
		for _, p := range ports {
			if common[p] {
				next[p] = true
			}
		}
		common = next
	}
	if len(common) > 0 {
		min := 65536
		for p := range common {
			if p < min {
				min = p
			}
		}
		for nodeID := range available {
			result[nodeID] = min
		}
		return result, nil
	}
	for nodeID, ports := range available {
		if len(ports) == 0 {
			return nil, errors.New("暂无可用端口")
		}
		result[nodeID] = ports[0]
	}
	return result, nil
}

func (a *App) availablePorts(nodeID int, excludeForwardID int) ([]int, error) {
	node, err := a.queryOne(`SELECT port FROM node WHERE id=?`, nodeID)
	if err != nil {
		return nil, errors.New("节点不存在")
	}
	used := map[int]bool{}
	chains, _ := a.queryMaps(`SELECT port FROM chain_tunnel WHERE node_id=? AND port IS NOT NULL`, nodeID)
	for _, c := range chains {
		used[intVal(c["port"], 0)] = true
	}
	forwards, _ := a.queryMaps(`SELECT port FROM forward_port WHERE node_id=? AND forward_id<>?`, nodeID, excludeForwardID)
	for _, f := range forwards {
		used[intVal(f["port"], 0)] = true
	}
	var out []int
	for _, p := range parsePorts(strVal(node["port"])) {
		if !used[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

func containsInt(items []int, target int) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func (a *App) reallocateForwardPorts(forwardID int, tunnelID int, inPort int) error {
	tx, _ := a.db.Begin()
	ports, err := a.allocateForwardPorts(tx, tunnelID, inPort, int64(forwardID))
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for nodeID, port := range ports {
		_, _ = tx.Exec(`UPDATE forward_port SET port=? WHERE forward_id=? AND node_id=?`, port, forwardID, nodeID)
	}
	return tx.Commit()
}

func (a *App) updateForwardServices(forwardID int) (bool, error) {
	return a.applyForwardServices(forwardID, "UpdateService")
}

func (a *App) applyForwardServices(forwardID int, method string) (bool, error) {
	fwd, err := a.queryOne(`SELECT * FROM forward WHERE id=?`, forwardID)
	if err != nil {
		return false, errors.New("转发不存在")
	}
	if over, msg := forwardLimitMessage(fwd); over {
		return false, errors.New(msg)
	}
	tunnel, err := a.queryOne(`SELECT * FROM tunnel WHERE id=?`, intVal(fwd["tunnelId"], 0))
	if err != nil {
		return false, errors.New("隧道不存在")
	}
	ut, _ := a.queryOne(`SELECT * FROM user_tunnel WHERE user_id=? AND tunnel_id=?`, intVal(fwd["userId"], 0), intVal(fwd["tunnelId"], 0))
	userTunnelID := intVal(ut["id"], 0)
	limiter := nullableInt(ut["speedId"])
	ports, _ := a.queryMaps(`SELECT * FROM forward_port WHERE forward_id=?`, forwardID)
	serviceName := buildServiceName(forwardID, intVal(fwd["userId"], 0), userTunnelID)
	for _, fp := range ports {
		nodeID := intVal(fp["nodeId"], 0)
		node, err := a.queryOne(`SELECT * FROM node WHERE id=?`, nodeID)
		if err != nil {
			return false, errors.New("部分节点不存在")
		}
		payload := buildForwardServices(serviceName, limiter, node, fwd, fp, tunnel)
		resp, err := a.sendAgentCommand(int64(nodeID), method, payload)
		if err != nil || (resp.Message != "OK" && !strings.Contains(resp.Message, "exists")) {
			if method == "UpdateService" && strings.Contains(commandError(resp, err), "not found") {
				resp, err = a.sendAgentCommand(int64(nodeID), "AddService", payload)
				if err == nil && (resp.Message == "OK" || strings.Contains(resp.Message, "exists")) {
					continue
				}
			}
			return false, errors.New(commandError(resp, err))
		}
	}
	return true, nil
}

func buildForwardServices(name string, limiter any, node map[string]any, fwd map[string]any, fp map[string]any, tunnel map[string]any) []any {
	var services []any
	for _, protocol := range []string{"tcp", "udp"} {
		addr := strDefault(strVal(node["tcpListenAddr"]), "[::]") + ":" + strconv.Itoa(intVal(fp["port"], 0))
		if protocol == "udp" {
			addr = strDefault(strVal(node["udpListenAddr"]), "[::]") + ":" + strconv.Itoa(intVal(fp["port"], 0))
		}
		service := map[string]any{
			"name":     name + "_" + protocol,
			"addr":     addr,
			"handler":  map[string]any{"type": protocol},
			"listener": createListener(protocol),
			"forwarder": map[string]any{
				"nodes":    forwarderNodes(strVal(fwd["remoteAddr"])),
				"selector": map[string]any{"strategy": strDefault(strVal(fwd["strategy"]), "fifo"), "maxFails": 1, "failTimeout": "600s"},
			},
		}
		if limiter != nil {
			service["limiter"] = fmt.Sprint(limiter)
		}
		if intVal(tunnel["type"], 1) == 2 {
			service["handler"].(map[string]any)["chain"] = "chains_" + strconv.Itoa(intVal(fwd["tunnelId"], 0))
		} else if iface := strVal(node["interfaceName"]); iface != "" {
			service["metadata"] = map[string]any{"interface": iface}
		}
		services = append(services, service)
	}
	return services
}

func createListener(protocol string) map[string]any {
	if protocol == "udp" {
		return map[string]any{"type": protocol, "metadata": map[string]any{"keepAlive": true}}
	}
	return map[string]any{"type": protocol}
}

func forwarderNodes(remoteAddr string) []any {
	var nodes []any
	for i, addr := range strings.Split(remoteAddr, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		nodes = append(nodes, map[string]any{"name": fmt.Sprintf("node_%d", i+1), "addr": addr})
	}
	return nodes
}

func buildServiceName(forwardID int, userID int, userTunnelID int) string {
	return strconv.Itoa(forwardID) + "_" + strconv.Itoa(userID) + "_" + strconv.Itoa(userTunnelID)
}

func (a *App) deleteForwardByID(id int, send bool) error {
	fwd, err := a.queryOne(`SELECT * FROM forward WHERE id=?`, id)
	if err != nil {
		return errors.New("转发不存在")
	}
	ut, _ := a.queryOne(`SELECT id FROM user_tunnel WHERE user_id=? AND tunnel_id=?`, intVal(fwd["userId"], 0), intVal(fwd["tunnelId"], 0))
	serviceName := buildServiceName(id, intVal(fwd["userId"], 0), intVal(ut["id"], 0))
	if send {
		entries, _ := a.queryMaps(`SELECT node_id FROM forward_port WHERE forward_id=?`, id)
		for _, entry := range entries {
			_, _ = a.sendAgentCommand(int64(intVal(entry["nodeId"], 0)), "DeleteService", map[string]any{
				"services": []string{serviceName + "_tcp", serviceName + "_udp"},
			})
		}
	}
	_, _ = a.db.Exec(`DELETE FROM forward_port WHERE forward_id=?`, id)
	_, _ = a.db.Exec(`DELETE FROM forward WHERE id=?`, id)
	return nil
}

func (a *App) changeForwardState(id int, status int) error {
	fwd, err := a.queryOne(`SELECT * FROM forward WHERE id=?`, id)
	if err != nil {
		return errors.New("转发不存在")
	}
	if status == 1 {
		if err := a.checkTunnelNodesActive(intVal(fwd["tunnelId"], 0)); err != nil {
			return err
		}
		if over, msg := forwardLimitMessage(fwd); over {
			_, _ = a.db.Exec(`UPDATE forward SET status=0,updated_time=? WHERE id=?`, nowMS(), id)
			return errors.New(msg)
		}
	}
	ut, _ := a.queryOne(`SELECT id FROM user_tunnel WHERE user_id=? AND tunnel_id=?`, intVal(fwd["userId"], 0), intVal(fwd["tunnelId"], 0))
	serviceName := buildServiceName(id, intVal(fwd["userId"], 0), intVal(ut["id"], 0))
	method := "PauseService"
	if status == 1 {
		method = "ResumeService"
	}
	entries, _ := a.queryMaps(`SELECT node_id FROM forward_port WHERE forward_id=?`, id)
	for _, entry := range entries {
		resp, err := a.sendAgentCommand(int64(intVal(entry["nodeId"], 0)), method, map[string]any{
			"services": []string{serviceName + "_tcp", serviceName + "_udp"},
		})
		if err != nil || resp.Message != "OK" {
			return errors.New(commandError(resp, err))
		}
	}
	_, _ = a.db.Exec(`UPDATE forward SET status=?,updated_time=? WHERE id=?`, status, nowMS(), id)
	return nil
}

func (a *App) fillForwardEntrances(forwards []map[string]any) {
	for _, f := range forwards {
		tunnel, err := a.queryOne(`SELECT in_ip FROM tunnel WHERE id=?`, intVal(f["tunnelId"], 0))
		if err != nil {
			continue
		}
		ports, _ := a.queryMaps(`SELECT fp.*, n.server_ip FROM forward_port fp LEFT JOIN node n ON n.id=fp.node_id WHERE fp.forward_id=?`, intVal(f["id"], 0))
		if len(ports) == 0 {
			continue
		}
		var addrs []string
		if inIP := strVal(tunnel["inIp"]); inIP != "" {
			seenPorts := map[int]bool{}
			for _, p := range ports {
				seenPorts[intVal(p["port"], 0)] = true
			}
			for _, ip := range strings.Split(inIP, ",") {
				for port := range seenPorts {
					addrs = append(addrs, strings.TrimSpace(ip)+":"+strconv.Itoa(port))
				}
			}
		} else {
			for _, p := range ports {
				addrs = append(addrs, strVal(p["serverIp"])+":"+strconv.Itoa(intVal(p["port"], 0)))
			}
		}
		f["inIp"] = strings.Join(addrs, ",")
		f["inPort"] = intVal(ports[0]["port"], 0)
	}
}

func (a *App) diagnoseTunnel(tunnelID int, remoteAddr string) []map[string]any {
	var results []map[string]any
	targets := parseTargets(remoteAddr)
	if len(targets) == 0 {
		targets = []targetAddr{{Host: "www.google.com", Port: 443}}
	}
	nodes, _ := a.queryMaps(`SELECT n.* FROM node n JOIN chain_tunnel ct ON ct.node_id=n.id WHERE ct.tunnel_id=? AND ct.chain_type=1`, tunnelID)
	for _, node := range nodes {
		for _, target := range targets {
			payload := map[string]any{"ip": target.Host, "port": target.Port, "count": 4, "timeout": 5000}
			resp, err := a.sendAgentCommand(int64(intVal(node["id"], 0)), "TcpPing", payload)
			result := map[string]any{
				"nodeId":      node["id"],
				"nodeName":    node["name"],
				"targetIp":    target.Host,
				"targetPort":  target.Port,
				"description": fmt.Sprintf("%s -> %s:%d", strVal(node["name"]), target.Host, target.Port),
				"timestamp":   nowMS(),
			}
			if err != nil || resp.Message != "OK" {
				result["success"] = false
				result["message"] = commandError(resp, err)
			} else {
				var data map[string]any
				_ = json.Unmarshal(resp.Data, &data)
				for k, v := range data {
					result[k] = v
				}
				if _, ok := result["success"]; !ok {
					result["success"] = true
				}
				result["message"] = "TCP连接成功"
			}
			results = append(results, result)
		}
	}
	return results
}

type targetAddr struct {
	Host string
	Port int
}

func parseTargets(remoteAddr string) []targetAddr {
	var out []targetAddr
	for _, raw := range strings.Split(remoteAddr, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(raw)
		if err != nil {
			idx := strings.LastIndex(raw, ":")
			if idx <= 0 {
				continue
			}
			host, portStr = raw[:idx], raw[idx+1:]
		}
		port, _ := strconv.Atoi(portStr)
		if host != "" && port > 0 {
			out = append(out, targetAddr{Host: strings.Trim(host, "[]"), Port: port})
		}
	}
	return out
}

func (a *App) applyLimiter(id int64) error {
	sl, err := a.queryOne(`SELECT * FROM speed_limit WHERE id=?`, id)
	if err != nil {
		return err
	}
	speed := fmt.Sprintf("%.1f", float64(intVal(sl["speed"], 0))/8.0)
	payload := map[string]any{
		"name": strconv.FormatInt(id, 10),
		"limits": []string{
			"$ " + speed + "MB " + speed + "MB",
		},
	}
	nodes, _ := a.queryMaps(`SELECT DISTINCT node_id FROM chain_tunnel WHERE tunnel_id=?`, intVal(sl["tunnelId"], 0))
	for _, n := range nodes {
		nodeID := int64(intVal(n["nodeId"], 0))
		resp, err := a.sendAgentCommand(nodeID, "UpdateLimiters", map[string]any{"limiter": strconv.FormatInt(id, 10), "data": payload})
		if err != nil || strings.Contains(commandError(resp, err), "not found") {
			resp, err = a.sendAgentCommand(nodeID, "AddLimiters", payload)
		}
		if err != nil || (resp.Message != "OK" && !strings.Contains(resp.Message, "exists")) {
			return errors.New(commandError(resp, err))
		}
	}
	return nil
}

func (a *App) processFlow(serviceName string, down int64, up int64) {
	parts := strings.Split(serviceName, "_")
	if len(parts) < 3 {
		return
	}
	forwardID, _ := strconv.Atoi(parts[0])
	userID, _ := strconv.Atoi(parts[1])
	userTunnelID, _ := strconv.Atoi(parts[2])
	if fwd, err := a.queryOne(`SELECT tunnel_id FROM forward WHERE id=?`, forwardID); err == nil {
		if tunnel, err := a.queryOne(`SELECT traffic_ratio,flow FROM tunnel WHERE id=?`, intVal(fwd["tunnelId"], 0)); err == nil {
			ratio := floatVal(tunnel["trafficRatio"], 1)
			mode := intVal(tunnel["flow"], 1)
			down = int64(float64(down) * ratio * float64(mode))
			up = int64(float64(up) * ratio * float64(mode))
		}
	}
	_, _ = a.db.Exec(`UPDATE forward SET in_flow=in_flow+?,out_flow=out_flow+? WHERE id=?`, down, up, forwardID)
	_, _ = a.db.Exec(`UPDATE user SET in_flow=in_flow+?,out_flow=out_flow+? WHERE id=?`, down, up, userID)
	if userTunnelID != 0 {
		_, _ = a.db.Exec(`UPDATE user_tunnel SET in_flow=in_flow+?,out_flow=out_flow+? WHERE id=?`, down, up, userTunnelID)
	}
	a.pauseForwardIfOverLimit(forwardID)
	a.pauseIfOverLimit(userID, userTunnelID)
}

func forwardLimitReached(flow int, expTime int, inFlow int, outFlow int) bool {
	if expTime > 0 && expTime <= int(nowMS()) {
		return true
	}
	if flow > 0 && flow != 99999 {
		used := int64(inFlow) + int64(outFlow)
		return used >= int64(flow)*bytesToGB
	}
	return false
}

func forwardLimitMessage(fwd map[string]any) (bool, string) {
	if exp := intVal(fwd["expTime"], 0); exp > 0 && exp <= int(nowMS()) {
		return true, "转发规则已到期"
	}
	if flow := intVal(fwd["flow"], 0); flow > 0 && flow != 99999 {
		used := int64(intVal(fwd["inFlow"], 0)) + int64(intVal(fwd["outFlow"], 0))
		if used >= int64(flow)*bytesToGB {
			return true, "转发规则流量已用完"
		}
	}
	return false, ""
}

func (a *App) pauseForwardIfOverLimit(forwardID int) bool {
	fwd, err := a.queryOne(`SELECT * FROM forward WHERE id=?`, forwardID)
	if err != nil || intVal(fwd["status"], 0) != 1 {
		return false
	}
	over, _ := forwardLimitMessage(fwd)
	if !over {
		return false
	}
	_ = a.changeForwardState(forwardID, 0)
	return true
}

func (a *App) pauseIfOverLimit(userID int, userTunnelID int) {
	user, err := a.queryOne(`SELECT * FROM user WHERE id=?`, userID)
	if err == nil {
		over := intVal(user["status"], 0) != 1
		if exp := intVal(user["expTime"], 0); exp > 0 && exp <= int(nowMS()) {
			over = true
		}
		if intVal(user["flow"], 0) > 0 && intVal(user["flow"], 0) != 99999 {
			over = over || int64(intVal(user["inFlow"], 0)+intVal(user["outFlow"], 0)) >= int64(intVal(user["flow"], 0))*bytesToGB
		}
		if over {
			forwards, _ := a.queryMaps(`SELECT id FROM forward WHERE user_id=? AND status=1`, userID)
			for _, f := range forwards {
				_ = a.changeForwardState(intVal(f["id"], 0), 0)
			}
			return
		}
	}
	if userTunnelID == 0 {
		return
	}
	ut, err := a.queryOne(`SELECT * FROM user_tunnel WHERE id=?`, userTunnelID)
	if err != nil {
		return
	}
	over := intVal(ut["status"], 0) != 1
	if exp := intVal(ut["expTime"], 0); exp > 0 && exp <= int(nowMS()) {
		over = true
	}
	if intVal(ut["flow"], 0) > 0 && intVal(ut["flow"], 0) != 99999 {
		over = over || int64(intVal(ut["inFlow"], 0)+intVal(ut["outFlow"], 0)) >= int64(intVal(ut["flow"], 0))*bytesToGB
	}
	if over {
		forwards, _ := a.queryMaps(`SELECT id FROM forward WHERE user_id=? AND tunnel_id=? AND status=1`, userID, intVal(ut["tunnelId"], 0))
		for _, f := range forwards {
			_ = a.changeForwardState(intVal(f["id"], 0), 0)
		}
	}
}

func (a *App) expiryLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		a.enforceExpiredForwards()
	}
}

func (a *App) nodeHealthLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.markStaleNodesOffline(25 * time.Second)
	}
}

func (a *App) markStaleNodesOffline(maxAge time.Duration) {
	cutoff := nowMS() - maxAge.Milliseconds()
	nodes, err := a.queryMaps(`SELECT id FROM node WHERE status=1 AND updated_time<?`, cutoff)
	if err != nil {
		return
	}
	for _, row := range nodes {
		id := int64(intVal(row["id"], 0))
		a.mu.RLock()
		active := a.nodes[id] != nil
		a.mu.RUnlock()
		if active {
			continue
		}
		_, _ = a.db.Exec(`UPDATE node SET status=0,updated_time=? WHERE id=?`, nowMS(), id)
		a.broadcast(map[string]any{"id": id, "type": "status", "data": 0})
	}
}

func (a *App) enforceExpiredForwards() {
	forwards, err := a.queryMaps(`SELECT id FROM forward WHERE status=1 AND ((exp_time>0 AND exp_time<=?) OR (flow>0 AND flow<>99999 AND (in_flow+out_flow)>=flow*?))`, nowMS(), bytesToGB)
	if err != nil {
		return
	}
	for _, fwd := range forwards {
		_ = a.changeForwardState(intVal(fwd["id"], 0), 0)
	}
}

func (a *App) closeNode(nodeID int64, code int, reason string) {
	a.mu.Lock()
	ns := a.nodes[nodeID]
	delete(a.nodes, nodeID)
	a.mu.Unlock()
	if ns != nil && ns.Conn != nil {
		_ = ns.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), nowDeadline())
		_ = ns.Conn.Close()
	}
}

func nowDeadline() time.Time {
	return time.Now().Add(2 * time.Second)
}

func processServerAddress(serverAddr string) string {
	serverAddr = stripAddressScheme(serverAddr)
	if strings.TrimSpace(serverAddr) == "" || strings.HasPrefix(serverAddr, "[") {
		return serverAddr
	}
	lastColon := strings.LastIndex(serverAddr, ":")
	if lastColon == -1 {
		if strings.Count(serverAddr, ":") >= 2 {
			return "[" + serverAddr + "]"
		}
		return serverAddr
	}
	host := serverAddr[:lastColon]
	port := serverAddr[lastColon:]
	if strings.Count(host, ":") >= 2 {
		return "[" + host + "]" + port
	}
	return serverAddr
}

func processAgentAddress(serverAddr string) string {
	addr := strings.TrimSpace(serverAddr)
	if idx := strings.Index(addr, "://"); idx >= 0 {
		scheme := addr[:idx+3]
		rest := addr[idx+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		if cut := strings.IndexAny(rest, "/?#"); cut >= 0 {
			rest = rest[:cut]
		}
		return scheme + rest
	}
	return processServerAddress(addr)
}

func stripAddressScheme(serverAddr string) string {
	addr := strings.TrimSpace(serverAddr)
	if idx := strings.Index(addr, "://"); idx >= 0 {
		addr = addr[idx+3:]
	}
	if at := strings.LastIndex(addr, "@"); at >= 0 {
		addr = addr[at+1:]
	}
	if idx := strings.IndexAny(addr, "/?#"); idx >= 0 {
		addr = addr[:idx]
	}
	return addr
}
