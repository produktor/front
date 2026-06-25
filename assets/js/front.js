(function () {
  'use strict';

  var SPHERE_RADIUS = 420;
  var mouseX = 0, mouseY = 0;
  var windowHalfX = window.innerWidth / 2;
  var windowHalfY = window.innerHeight / 2;
  var camera, scene, renderer, labelRenderer;
  var nodeMeshes = [];
  var nodeByMesh = new Map();
  var labelById = new Map();
  var lineSegments = null;
  var meshData = null;
  var activeTypes = { project: true, technology: true, product: true, domain: true };
  var activeTag = null;
  var pinnedId = null;
  var hoveredId = null;
  var raycaster = new THREE.Raycaster();
  var pointer = new THREE.Vector2();
  var colorByType = {
    project: 0x319177,
    technology: 0x052f5f,
    product: 0xd5c67a,
    domain: 0xf1a208
  };

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    fetch('assets/data/knowledge-mesh.json')
      .then(function (r) { return r.json(); })
      .then(buildMesh)
      .catch(function (err) {
        console.warn('knowledge mesh load failed, using fallback', err);
        buildFallback();
      });
  }

  function fibonacciSphere(i, n, radius) {
    var phi = Math.acos(1 - 2 * (i + 0.5) / n);
    var theta = Math.PI * (1 + Math.sqrt(5)) * i;
    return new THREE.Vector3(
      radius * Math.cos(theta) * Math.sin(phi),
      radius * Math.sin(theta) * Math.sin(phi),
      radius * Math.cos(phi)
    );
  }

  function setupScene() {
    var wrap = document.getElementById('canvas-wrap');
    camera = new THREE.PerspectiveCamera(70, window.innerWidth / window.innerHeight, 1, 10000);
    camera.position.z = 900;
    scene = new THREE.Scene();

    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 1);
    wrap.appendChild(renderer.domElement);

    labelRenderer = new THREE.CSS2DRenderer();
    labelRenderer.setSize(window.innerWidth, window.innerHeight);
    labelRenderer.domElement.style.position = 'absolute';
    labelRenderer.domElement.style.top = '0';
    labelRenderer.domElement.style.pointerEvents = 'none';
    wrap.appendChild(labelRenderer.domElement);

    document.addEventListener('mousemove', onPointerMove, false);
    document.addEventListener('click', onClick, false);
    document.addEventListener('touchstart', onTouchStart, { passive: false });
    document.addEventListener('touchmove', onTouchMove, { passive: false });
    window.addEventListener('resize', onWindowResize, false);
    animate();
  }

  function buildMesh(data) {
    meshData = data;
    setupScene();
    setupFilters(data.categories || []);
    rebuildGraph();
  }

  function setupFilters(categories) {
    var el = document.getElementById('filters');
    el.innerHTML = '';
    categories.forEach(function (cat) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'chip type-' + cat.id + ' active';
      btn.textContent = cat.label;
      btn.dataset.type = cat.id;
      btn.addEventListener('click', function () {
        activeTypes[cat.id] = !activeTypes[cat.id];
        btn.classList.toggle('active', activeTypes[cat.id]);
        rebuildGraph();
      });
      el.appendChild(btn);
    });

    var tags = collectTags(meshData.nodes);
    tags.slice(0, 12).forEach(function (tag) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'chip';
      btn.textContent = '#' + tag;
      btn.dataset.tag = tag;
      btn.addEventListener('click', function () {
        if (activeTag === tag) {
          activeTag = null;
          btn.classList.remove('active');
        } else {
          activeTag = tag;
          el.querySelectorAll('[data-tag]').forEach(function (b) { b.classList.remove('active'); });
          btn.classList.add('active');
        }
        rebuildGraph();
      });
      el.appendChild(btn);
    });
  }

  function collectTags(nodes) {
    var counts = {};
    nodes.forEach(function (n) {
      (n.tags || []).forEach(function (t) {
        counts[t] = (counts[t] || 0) + 1;
      });
    });
    return Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; });
  }

  function nodeVisible(node) {
    if (!activeTypes[node.type]) return false;
    if (activeTag && (!node.tags || node.tags.indexOf(activeTag) < 0)) return false;
    return true;
  }

  function setBufferAttribute(geometry, name, attribute) {
    if (typeof geometry.setAttribute === 'function') {
      geometry.setAttribute(name, attribute);
    } else {
      geometry.addAttribute(name, attribute);
    }
  }

  function rebuildGraph() {
    nodeMeshes.forEach(function (m) {
      scene.remove(m);
      if (m.geometry) m.geometry.dispose();
      if (m.material) m.material.dispose();
    });
    nodeMeshes = [];
    nodeByMesh.clear();
    labelById.clear();
    if (lineSegments) {
      scene.remove(lineSegments);
      lineSegments.geometry.dispose();
      lineSegments.material.dispose();
      lineSegments = null;
    }

    var visible = meshData.nodes.filter(nodeVisible);
    var visibleIds = {};
    visible.forEach(function (n, i) { visibleIds[n.id] = i; });

    visible.forEach(function (node, i) {
      var pos = fibonacciSphere(i, visible.length, SPHERE_RADIUS);
      var size = 4 + (node.weight || 2) * 2;
      var geo = new THREE.SphereGeometry(size, 10, 10);
      var mat = new THREE.MeshBasicMaterial({
        color: colorByType[node.type] || 0xffffff,
        transparent: true,
        opacity: 0.9
      });
      var mesh = new THREE.Mesh(geo, mat);
      mesh.position.copy(pos);
      mesh.userData = { id: node.id, node: node };
      scene.add(mesh);
      nodeMeshes.push(mesh);
      nodeByMesh.set(mesh, node);

      var labelEl = document.createElement('div');
      labelEl.className = 'label-node';
      labelEl.textContent = node.label;
      var label = new THREE.CSS2DObject(labelEl);
      label.position.set(0, size + 6, 0);
      mesh.add(label);
      labelById.set(node.id, label);
    });

    var edgePositions = [];
    meshData.edges.forEach(function (edge) {
      if (visibleIds[edge.source] === undefined || visibleIds[edge.target] === undefined) return;
      var a = nodeMeshes[visibleIds[edge.source]].position;
      var b = nodeMeshes[visibleIds[edge.target]].position;
      edgePositions.push(a.x, a.y, a.z, b.x, b.y, b.z);
    });

    if (edgePositions.length) {
      var buf = new THREE.BufferAttribute(new Float32Array(edgePositions), 3);
      var lineGeo = new THREE.BufferGeometry();
      setBufferAttribute(lineGeo, 'position', buf);
      lineSegments = new THREE.LineSegments(
        lineGeo,
        new THREE.LineBasicMaterial({ color: 0x444444, transparent: true, opacity: 0.35 })
      );
      scene.add(lineSegments);
    }

    updateDetail(pinnedId ? findNode(pinnedId) : null);
  }

  function findNode(id) {
    if (!meshData) return null;
    for (var i = 0; i < meshData.nodes.length; i++) {
      if (meshData.nodes[i].id === id) return meshData.nodes[i];
    }
    return null;
  }

  function updateDetail(node) {
    var el = document.getElementById('detail');
    if (!node) {
      el.innerHTML = '<span class="muted">Hover or click a node</span>';
      return;
    }
    var html = '<b>' + escapeHtml(node.label) + '</b>';
    if (node.period) html += ' <span class="muted">(' + escapeHtml(node.period) + ')</span>';
    if (node.type) html += '<br><span class="muted">' + escapeHtml(node.type) + '</span>';
    if (node.tags && node.tags.length) {
      html += '<div class="tags">';
      node.tags.forEach(function (t) { html += '<span>#' + escapeHtml(t) + '</span>'; });
      html += '</div>';
    }
    if (node.url) {
      html += '<br><a href="' + escapeHtml(node.url) + '" target="_blank" rel="noopener">open →</a>';
    }
    el.innerHTML = html;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function setLabelState(id, state) {
    var label = labelById.get(id);
    if (!label) return;
    var el = label.element;
    el.classList.toggle('visible', state === 'hover' || state === 'pinned');
    el.classList.toggle('pinned', state === 'pinned');
  }

  function clearHover() {
    if (hoveredId && hoveredId !== pinnedId) setLabelState(hoveredId, null);
    hoveredId = null;
    nodeMeshes.forEach(function (m) {
      m.material.opacity = 0.9;
      m.scale.set(1, 1, 1);
    });
  }

  function pick(clientX, clientY) {
    pointer.x = (clientX / window.innerWidth) * 2 - 1;
    pointer.y = -(clientY / window.innerHeight) * 2 + 1;
    raycaster.setFromCamera(pointer, camera);
    var hits = raycaster.intersectObjects(nodeMeshes);
    return hits.length ? hits[0].object : null;
  }

  function onPointerMove(event) {
    mouseX = event.clientX - windowHalfX;
    mouseY = event.clientY - windowHalfY;
    var mesh = pick(event.clientX, event.clientY);
    if (!mesh) {
      clearHover();
      if (!pinnedId) updateDetail(null);
      return;
    }
    var node = nodeByMesh.get(mesh);
    if (hoveredId !== node.id) {
      clearHover();
      hoveredId = node.id;
      if (pinnedId !== node.id) setLabelState(node.id, 'hover');
      mesh.material.opacity = 1;
      mesh.scale.set(1.3, 1.3, 1.3);
      if (!pinnedId) updateDetail(node);
    }
  }

  function onClick(event) {
    var mesh = pick(event.clientX, event.clientY);
    if (!mesh) {
      pinnedId = null;
      labelById.forEach(function (_, id) { setLabelState(id, null); });
      updateDetail(null);
      return;
    }
    var node = nodeByMesh.get(mesh);
    if (pinnedId === node.id) {
      if (node.url) window.open(node.url, '_blank', 'noopener');
      return;
    }
    pinnedId = node.id;
    labelById.forEach(function (_, id) {
      setLabelState(id, id === pinnedId ? 'pinned' : null);
    });
    updateDetail(node);
  }

  function onTouchStart(event) {
    if (event.touches.length === 1) {
      event.preventDefault();
      mouseX = event.touches[0].pageX - windowHalfX;
      mouseY = event.touches[0].pageY - windowHalfY;
      onPointerMove({ clientX: event.touches[0].pageX, clientY: event.touches[0].pageY });
    }
  }

  function onTouchMove(event) {
    if (event.touches.length === 1) {
      event.preventDefault();
      mouseX = event.touches[0].pageX - windowHalfX;
      mouseY = event.touches[0].pageY - windowHalfY;
    }
  }

  function onWindowResize() {
    windowHalfX = window.innerWidth / 2;
    windowHalfY = window.innerHeight / 2;
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
    labelRenderer.setSize(window.innerWidth, window.innerHeight);
  }

  function animate() {
    requestAnimationFrame(animate);
    if (camera) {
      camera.position.x += (mouseX - camera.position.x) * 0.05;
      camera.position.y += (-mouseY + 200 - camera.position.y) * 0.05;
      camera.lookAt(scene.position);
      renderer.render(scene, camera);
      labelRenderer.render(scene, camera);
    }
  }

  function buildFallback() {
    meshData = {
      categories: [],
      nodes: [],
      edges: []
    };
    for (var i = 0; i < 100; i++) {
      meshData.nodes.push({ id: 'n' + i, label: '', type: 'technology', weight: 1, tags: [] });
    }
    setupScene();
    rebuildGraph();
  }
})();
