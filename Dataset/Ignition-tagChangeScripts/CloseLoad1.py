def valueChanged(tag, tagPath, previousValue, currentValue, initialChange, missedEvents):
	
	current_value = currentValue.value
						
	if current_value == True:
		system.tag.write('[default]C1', 0)
		system.tag.write('[default]R1', 0)
		system.tag.write('[default]CloseLoad1', False)
		system.tag.write('[default]DecLoad1', False)
		system.tag.write('[default]IncLoad1', False)