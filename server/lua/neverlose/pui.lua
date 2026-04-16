-- Compact neverlose/pui stub.
-- Keep this library small: large reqitem payloads can trip the client's
-- string cleanup path in this build.

local node_mt = {}

local function value(v)
    if v == nil then
        return setmetatable({}, node_mt)
    end
    return v
end

local function node()
    return setmetatable({}, node_mt)
end

node_mt.__index = function()
    return function(...)
        return node()
    end
end

node_mt.__call = function()
    return node()
end

local pui = {}

function pui.create(...)
    return node(...)
end

function pui.group(...)
    return node(...)
end

function pui.window(...)
    return node(...)
end

function pui.child(...)
    return node(...)
end

function pui.tab(...)
    return node(...)
end

function pui.button(...)
    return node(...)
end

function pui.checkbox(...)
    return node(...)
end

function pui.switch(...)
    return node(...)
end

function pui.combo(...)
    return node(...)
end

function pui.multiselect(...)
    return node(...)
end

function pui.slider(...)
    return node(...)
end

function pui.color_picker(...)
    return node(...)
end

function pui.text_input(...)
    return node(...)
end

function pui.label(...)
    return node(...)
end

function pui.text(...)
    return node(...)
end

function pui.hotkey(...)
    return node(...)
end

function pui.list(...)
    return node(...)
end

function pui.get(...)
    return nil
end

function pui.set(...)
    return nil
end

function pui.reference(...)
    return node(...)
end

return setmetatable(pui, {
    __index = function(_, k)
        return value(rawget(pui, k))
    end,
    __call = function()
        return node()
    end,
})
