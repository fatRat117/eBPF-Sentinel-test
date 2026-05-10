package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// Hub 管理所有WebSocket连接
// 负责客户端的注册、注销和消息广播
type Hub struct {
	clients    map[*Client]bool // 已连接的客户端映射
	broadcast  chan []byte      // 广播消息通道
	register   chan *Client     // 客户端注册通道
	unregister chan *Client     // 客户端注销通道
	mu         sync.RWMutex     // 读写锁保护clients映射
}

// Client 表示一个WebSocket客户端连接
type Client struct {
	hub  *Hub            // 所属的Hub
	conn *websocket.Conn // WebSocket连接
	send chan []byte     // 发送消息通道（带缓冲）
}

// WebSocket升级器配置
// CheckOrigin允许所有来源（生产环境应该限制）
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有来源
	},
}

// NewHub 创建新的Hub实例
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run 启动Hub的主循环
// 处理客户端注册、注销和消息广播
// 此函数应该在一个独立的goroutine中运行
func (h *Hub) Run() {
	for {
		select {
		// 处理新客户端连接
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("[WebSocket] Client connected, total: %d", len(h.clients))

		// 处理客户端断开连接
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("[WebSocket] Client disconnected, total: %d", len(h.clients))

		// 广播消息给所有客户端
		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				// 尝试发送消息
				case client.send <- message:
				default:
					// 客户端发送缓冲区满，关闭连接
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast 广播消息给所有连接的客户端
// data会被序列化为JSON格式
func (h *Hub) Broadcast(data interface{}) {
	message, err := json.Marshal(data)
	if err != nil {
		log.Printf("[WebSocket] Failed to marshal message: %v", err)
		return
	}

	// 非阻塞发送
	select {
	case h.broadcast <- message:
	default:
		log.Println("[WebSocket] Broadcast channel full, dropping message")
	}
}

// BroadcastRaw 广播原始字节消息
func (h *Hub) BroadcastRaw(message []byte) {
	select {
	case h.broadcast <- message:
	default:
		log.Println("[WebSocket] Broadcast channel full, dropping message")
	}
}

// ServeWs 处理WebSocket连接升级请求
// 将HTTP连接升级为WebSocket连接
func (h *Hub) ServeWs(w http.ResponseWriter, r *http.Request) {
	// 升级HTTP连接为WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebSocket] Upgrade error: %v", err)
		return
	}

	// 创建客户端实例
	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}

	// 注册到Hub
	h.register <- client

	// 启动读写goroutine
	go client.writePump()
	go client.readPump()
}

// readPump 从客户端读取消息
// 持续读取客户端发送的消息，直到连接断开
func (c *Client) readPump() {
	defer func() {
		// 连接断开时注销客户端
		c.hub.unregister <- c
		c.conn.Close()
	}()

	// 设置读取限制（防止内存攻击）
	c.conn.SetReadLimit(512)

	for {
		// 读取消息（这里只读取不处理，因为客户端主要是接收数据）
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[WebSocket] Read error: %v", err)
			}
			break
		}
		// 可以在这里处理客户端发来的命令
	}
}

// writePump 向客户端发送消息
// 持续从send通道读取消息并发送给客户端
func (c *Client) writePump() {
	defer func() {
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			// 通道关闭
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// 发送消息
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("[WebSocket] Write error: %v", err)
				return
			}
		}
	}
}

// ClientCount 返回当前连接的客户端数量
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
